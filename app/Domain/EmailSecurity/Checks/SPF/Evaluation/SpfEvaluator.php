<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParsedTerm;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;

final class SpfEvaluator
{
    private const MAX_DEPTH = 32;
    private const MAX_REDIRECT_CHAIN = 3;

    private SpfLookupCounter $lookupCounter;

    public function __construct(
        private SpfDnsDependencyResolver $resolver,
    ) {
        $this->lookupCounter = new SpfLookupCounter();
    }

    /**
     * @param list<SpfParsedTerm> $terms
     */
    public function evaluate(array $terms, string $domain, SpfValidationResult $validation): SpfEvaluationResult
    {
        $this->resolver->reset();
        $this->lookupCounter = new SpfLookupCounter();

        $resolvedIps = [];
        $dependencies = [];
        $warnings = [];
        $errors = [];
        $diagnostics = [];

        $this->walkTerms(
            terms: $terms,
            domain: strtolower(trim($domain)),
            resolvedIps: $resolvedIps,
            dependencies: $dependencies,
            warnings: $warnings,
            errors: $errors,
            diagnostics: $diagnostics,
            visitedDomains: [],
            depth: 0,
            redirectChain: [],
            parentMechanism: null,
        );

        foreach ($validation->warnings as $warning) {
            $warnings[] = $warning;
        }

        if ($this->lookupCounter->voidCount() >= 2) {
            $warnings[] = ['code' => 'VOID_LOOKUP_WARNING', 'message' => 'SPF void lookup count is elevated.'];
        }
        if ($this->lookupCounter->voidCount() > 2) {
            $errors[] = ['code' => 'VOID_LOOKUP_LIMIT', 'message' => 'SPF void lookup limit exceeded.'];
        }

        if ($this->lookupCounter->exceeded()) {
            $errors[] = ['code' => 'LOOKUP_LIMIT', 'message' => 'SPF exceeds the 10-lookup limit.'];
        }

        return new SpfEvaluationResult(
            resolvedIps: array_values(array_unique($resolvedIps)),
            dependencies: $dependencies,
            warnings: $warnings,
            errors: $errors,
            diagnostics: $diagnostics,
            lookupLimitExceeded: $this->lookupCounter->exceeded(),
        );
    }

    public function lookupCounter(): SpfLookupCounter
    {
        return $this->lookupCounter;
    }

    /**
     * @param list<SpfParsedTerm> $terms
     * @param list<string> $resolvedIps
     * @param list<array<string, mixed>> $dependencies
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array{code: string, message: string}> $errors
     * @param list<array<string, mixed>> $diagnostics
     * @param list<string> $visitedDomains
     * @param list<string> $redirectChain
     */
    private function walkTerms(
        array $terms,
        string $domain,
        array &$resolvedIps,
        array &$dependencies,
        array &$warnings,
        array &$errors,
        array &$diagnostics,
        array $visitedDomains,
        int $depth,
        array $redirectChain,
        ?string $parentMechanism,
    ): void {
        if ($depth > self::MAX_DEPTH) {
            $errors[] = ['code' => 'PERMERROR_DEPTH', 'message' => 'SPF recursion depth limit exceeded.'];

            return;
        }

        if (in_array($domain, $visitedDomains, true)) {
            $warnings[] = ['code' => 'LOOP_DETECTED', 'message' => 'SPF include/redirect loop detected.'];

            return;
        }

        $visitedDomains[] = $domain;

        foreach ($terms as $term) {
            if ($term->type === 'modifier' && $term->name === 'redirect') {
                $this->processRedirect($term, $domain, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth, $redirectChain);

                return;
            }

            $this->processMechanism($term, $domain, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth, $redirectChain, $parentMechanism);

            if ($term->name === 'all') {
                break;
            }
        }
    }

    /**
     * @param list<string> $resolvedIps
     * @param list<array<string, mixed>> $dependencies
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array{code: string, message: string}> $errors
     * @param list<array<string, mixed>> $diagnostics
     * @param list<string> $visitedDomains
     * @param list<string> $redirectChain
     */
    private function processMechanism(
        SpfParsedTerm $term,
        string $domain,
        array &$resolvedIps,
        array &$dependencies,
        array &$warnings,
        array &$errors,
        array &$diagnostics,
        array $visitedDomains,
        int $depth,
        array $redirectChain,
        ?string $parentMechanism,
    ): void {
        switch ($term->name) {
            case 'ip4':
            case 'ip6':
                if ($term->argument !== null) {
                    $suffix = $term->cidrV4 !== null ? '/' . $term->cidrV4 : ($term->cidrV6 !== null ? '/' . $term->cidrV6 : '');
                    $resolvedIps[] = $term->argument . $suffix;
                }
                break;

            case 'include':
                $target = $this->expandDomain($term->argument, $domain);
                if (!$this->lookupCounter->increment('include', $target, 'TXT', $parentMechanism)) {
                    return;
                }
                $child = $this->fetchSpfRecord($target, $diagnostics);
                $dependencies[] = ['mechanism' => 'include', 'domain' => $target, 'record' => $child];
                if ($child === null) {
                    $this->lookupCounter->recordVoid('include', $target, 'TXT', 'NXDOMAIN or empty');
                    $warnings[] = ['code' => 'INCLUDE_NXDOMAIN', 'message' => "Include target {$target} has no SPF record."];
                } else {
                    $childTerms = (new \App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser())->parse($child, $target);
                    $this->walkTerms($childTerms, $target, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth + 1, $redirectChain, 'include');
                }
                break;

            case 'a':
                $target = $this->expandDomain($term->argument ?? $domain, $domain);
                if (!$this->lookupCounter->increment('a', $target, 'A/AAAA', $parentMechanism)) {
                    return;
                }
                $this->resolveAddresses($target, $resolvedIps, $diagnostics, 'a');
                break;

            case 'mx':
                $target = $this->expandDomain($term->argument ?? $domain, $domain);
                if (!$this->lookupCounter->increment('mx', $target, 'MX', $parentMechanism)) {
                    return;
                }
                $mxResult = $this->resolver->mx($target);
                $diagnostics[] = ['type' => 'MX', 'host' => $target, 'records' => $mxResult->records];
                if ($mxResult->empty) {
                    $this->lookupCounter->recordVoid('mx', $target, 'MX', 'empty');
                }
                foreach ($mxResult->records as $mxHost) {
                    $this->resolveAddresses($mxHost, $resolvedIps, $diagnostics, 'mx');
                }
                break;

            case 'exists':
                $target = $this->expandDomain($term->argument, $domain);
                if (!$this->lookupCounter->increment('exists', $target, 'TXT', $parentMechanism)) {
                    return;
                }
                $exists = $this->resolver->txt($target);
                $diagnostics[] = ['type' => 'TXT', 'host' => $target, 'records' => $exists->records];
                if ($exists->empty || $exists->failed()) {
                    $this->lookupCounter->recordVoid('exists', $target, 'TXT', 'empty or failed');
                }
                break;

            case 'ptr':
                if (!$this->lookupCounter->increment('ptr', $domain, 'PTR', $parentMechanism)) {
                    return;
                }
                break;

            case 'all':
                break;
        }
    }

    /**
     * @param list<string> $resolvedIps
     * @param list<array<string, mixed>> $dependencies
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array{code: string, message: string}> $errors
     * @param list<array<string, mixed>> $diagnostics
     * @param list<string> $visitedDomains
     * @param list<string> $redirectChain
     */
    private function processRedirect(
        SpfParsedTerm $term,
        string $domain,
        array &$resolvedIps,
        array &$dependencies,
        array &$warnings,
        array &$errors,
        array &$diagnostics,
        array $visitedDomains,
        int $depth,
        array $redirectChain,
    ): void {
        $target = $this->expandDomain($term->argument, $domain);
        $redirectChain[] = $target;
        if (count($redirectChain) > self::MAX_REDIRECT_CHAIN) {
            $warnings[] = ['code' => 'REDIRECT_CHAIN_LONG', 'message' => 'SPF redirect chain is too long.'];

            return;
        }

        if (!$this->lookupCounter->increment('redirect', $target, 'TXT', 'redirect')) {
            return;
        }

        $child = $this->fetchSpfRecord($target, $diagnostics);
        $dependencies[] = ['mechanism' => 'redirect', 'domain' => $target, 'record' => $child];
        if ($child === null) {
            $this->lookupCounter->recordVoid('redirect', $target, 'TXT', 'NXDOMAIN or empty');
            $warnings[] = ['code' => 'INCLUDE_NXDOMAIN', 'message' => "Redirect target {$target} has no SPF record."];
        } else {
            $childTerms = (new \App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser())->parse($child, $target);
            $this->walkTerms($childTerms, $target, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth + 1, $redirectChain, 'redirect');
        }
    }

    /**
     * @param list<array<string, mixed>> $diagnostics
     */
    private function fetchSpfRecord(string $domain, array &$diagnostics): ?string
    {
        $result = $this->resolver->txt($domain);
        $diagnostics[] = ['type' => 'TXT', 'host' => $domain, 'records' => $result->records, 'error' => $result->error];

        if ($result->failed()) {
            return null;
        }

        $matches = [];
        foreach ($result->records as $record) {
            if (SpfRecordDiscovery::isSpfRecord($record)) {
                $matches[] = $record;
            }
        }

        return $matches[0] ?? null;
    }

    /**
     * @param list<string> $resolvedIps
     * @param list<array<string, mixed>> $diagnostics
     */
    private function resolveAddresses(string $host, array &$resolvedIps, array &$diagnostics, string $parent): void
    {
        $a = $this->resolver->a($host);
        $aaaa = $this->resolver->aaaa($host);
        $diagnostics[] = ['type' => 'A', 'host' => $host, 'records' => $a->records, 'parent' => $parent];
        $diagnostics[] = ['type' => 'AAAA', 'host' => $host, 'records' => $aaaa->records, 'parent' => $parent];
        foreach (array_merge($a->records, $aaaa->records) as $ip) {
            $resolvedIps[] = $ip;
        }
    }

    private function expandDomain(?string $value, string $baseDomain): string
    {
        $value = strtolower(trim((string) $value));

        return str_replace('%{d}', $baseDomain, $value);
    }
}
