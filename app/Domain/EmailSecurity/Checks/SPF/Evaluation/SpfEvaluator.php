<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAssessment;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParsedTerm;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;

final class SpfEvaluator
{
    private const MAX_DEPTH = 32;
    private const MAX_REDIRECT_CHAIN = 3;

    private SpfLookupCounter $lookupCounter;
    private bool $hasTemperror = false;

    public function __construct(
        private SpfDnsDependencyResolver $resolver,
        private SpfParser $parser,
    ) {
        $this->lookupCounter = new SpfLookupCounter();
    }

    /**
     * @param list<SpfParsedTerm> $terms
     */
    public function evaluate(
        array $terms,
        string $domain,
        SpfValidationResult $validation,
        ?SpfMacroAssessment $macroAssessment = null,
    ): SpfEvaluationResult {
        $this->resolver->reset();
        $this->lookupCounter = new SpfLookupCounter();
        $this->hasTemperror = false;

        $resolvedIps = [];
        $dependencies = [];
        $warnings = [];
        $errors = [];
        $diagnostics = [];

        $this->walkTerms(
            terms: $terms,
            domain: strtolower(trim($domain)),
            validation: $validation,
            macroAssessment: $macroAssessment,
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

        if ($this->lookupCounter->attemptedOverLimit()) {
            $errors[] = ['code' => 'LOOKUP_LIMIT', 'message' => 'SPF exceeds the 10-lookup limit.'];
        }

        return new SpfEvaluationResult(
            resolvedIps: array_values(array_unique($resolvedIps)),
            dependencies: $dependencies,
            warnings: $warnings,
            errors: $errors,
            diagnostics: $diagnostics,
            lookupLimitExceeded: $this->lookupCounter->attemptedOverLimit(),
            hasTemperror: $this->hasTemperror,
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
        SpfValidationResult $validation,
        ?SpfMacroAssessment $macroAssessment,
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

        $redirectTerm = null;
        foreach ($terms as $term) {
            if ($term->type === 'modifier' && $term->name === 'redirect') {
                $redirectTerm = $term;
            }
        }

        foreach ($terms as $term) {
            if ($term->type === 'modifier') {
                continue;
            }

            $this->processMechanism(
                $term,
                $domain,
                $macroAssessment,
                $resolvedIps,
                $dependencies,
                $warnings,
                $errors,
                $diagnostics,
                $visitedDomains,
                $depth,
                $redirectChain,
                $parentMechanism,
            );

            if ($term->name === 'all') {
                break;
            }
        }

        if ($redirectTerm !== null && !$validation->hasTerminalAll) {
            $this->processRedirect(
                $redirectTerm,
                $domain,
                $macroAssessment,
                $resolvedIps,
                $dependencies,
                $warnings,
                $errors,
                $diagnostics,
                $visitedDomains,
                $depth,
                $redirectChain,
            );
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
        ?SpfMacroAssessment $macroAssessment,
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
                if ($this->macroBlocksEvaluation($term, $macroAssessment)) {
                    break;
                }
                $target = $this->expandDomain($term->argument, $domain);
                if (!$this->lookupCounter->increment('include', $target, 'TXT', $parentMechanism)) {
                    return;
                }
                $child = $this->fetchSpfRecord($target, $diagnostics, $errors, 'include');
                $dependencies[] = ['mechanism' => 'include', 'domain' => $target, 'record' => $child];
                if ($child === null && !$this->hasTemperror) {
                    $errors[] = ['code' => 'INCLUDE_NONE_PERMERROR', 'message' => "Include target {$target} has no SPF record."];
                } elseif ($child !== null) {
                    $childTerms = $this->parser->parse($child, $target);
                    $childValidation = new SpfValidationResult(terms: $childTerms);
                    $this->walkTerms($childTerms, $target, $childValidation, $macroAssessment, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth + 1, $redirectChain, 'include');
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
                $diagnostics[] = ['type' => 'MX', 'host' => $target, 'records' => $mxResult->records, 'outcome' => $mxResult->outcome];
                if ($mxResult->isVoidEligible()) {
                    $this->lookupCounter->recordVoid('mx', $target, 'MX', $mxResult->outcome);
                }
                foreach ($mxResult->records as $mxHost) {
                    $this->resolveAddresses($mxHost, $resolvedIps, $diagnostics, 'mx');
                }
                break;

            case 'exists':
                if ($this->macroBlocksEvaluation($term, $macroAssessment)) {
                    break;
                }
                $target = $this->expandDomain($term->argument, $domain);
                if (!$this->lookupCounter->increment('exists', $target, 'TXT', $parentMechanism)) {
                    return;
                }
                $exists = $this->resolver->txt($target);
                $diagnostics[] = ['type' => 'TXT', 'host' => $target, 'records' => $exists->records, 'outcome' => $exists->outcome];
                if ($exists->isTemperror()) {
                    $this->recordTemperror($errors, $target);
                } elseif ($exists->isVoidEligible()) {
                    $this->lookupCounter->recordVoid('exists', $target, 'TXT', $exists->outcome);
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
        ?SpfMacroAssessment $macroAssessment,
        array &$resolvedIps,
        array &$dependencies,
        array &$warnings,
        array &$errors,
        array &$diagnostics,
        array $visitedDomains,
        int $depth,
        array $redirectChain,
    ): void {
        if ($this->macroBlocksEvaluation($term, $macroAssessment)) {
            return;
        }

        $target = $this->expandDomain($term->argument, $domain);
        $redirectChain[] = $target;
        if (count($redirectChain) > self::MAX_REDIRECT_CHAIN) {
            $warnings[] = ['code' => 'REDIRECT_CHAIN_LONG', 'message' => 'SPF redirect chain is too long.'];

            return;
        }

        if (!$this->lookupCounter->increment('redirect', $target, 'TXT', 'redirect')) {
            return;
        }

        $child = $this->fetchSpfRecord($target, $diagnostics, $errors, 'redirect');
        $dependencies[] = ['mechanism' => 'redirect', 'domain' => $target, 'record' => $child];
        if ($child === null && !$this->hasTemperror) {
            $errors[] = ['code' => 'REDIRECT_NONE_PERMERROR', 'message' => "Redirect target {$target} has no SPF record."];
        } elseif ($child !== null) {
            $childTerms = $this->parser->parse($child, $target);
            $childValidation = new SpfValidationResult(terms: $childTerms);
            $this->walkTerms($childTerms, $target, $childValidation, $macroAssessment, $resolvedIps, $dependencies, $warnings, $errors, $diagnostics, $visitedDomains, $depth + 1, $redirectChain, 'redirect');
        }
    }

    /**
     * @param list<array<string, mixed>> $diagnostics
     * @param list<array{code: string, message: string}> $errors
     */
    private function fetchSpfRecord(string $domain, array &$diagnostics, array &$errors, string $context): ?string
    {
        $result = $this->resolver->txt($domain);
        $diagnostics[] = ['type' => 'TXT', 'host' => $domain, 'records' => $result->records, 'error' => $result->error, 'outcome' => $result->outcome, 'context' => $context];

        if ($result->isTemperror()) {
            $this->recordTemperror($errors, $domain);

            return null;
        }

        if ($result->isVoidEligible()) {
            $this->lookupCounter->recordVoid($context, $domain, 'TXT', $result->outcome);

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
        $diagnostics[] = ['type' => 'A', 'host' => $host, 'records' => $a->records, 'parent' => $parent, 'outcome' => $a->outcome];
        $diagnostics[] = ['type' => 'AAAA', 'host' => $host, 'records' => $aaaa->records, 'parent' => $parent, 'outcome' => $aaaa->outcome];
        foreach (array_merge($a->records, $aaaa->records) as $ip) {
            $resolvedIps[] = $ip;
        }
    }

    /**
     * @param list<array{code: string, message: string}> $errors
     */
    private function recordTemperror(array &$errors, string $domain): void
    {
        $this->hasTemperror = true;
        $errors[] = ['code' => 'DNS_TEMPERROR', 'message' => "Temporary DNS failure while resolving {$domain}."];
    }

    private function macroBlocksEvaluation(SpfParsedTerm $term, ?SpfMacroAssessment $macroAssessment): bool
    {
        if ($macroAssessment === null || !$macroAssessment->hasUnsupportedMacro) {
            return false;
        }

        $value = (string) $term->argument;
        if ($value === '') {
            return false;
        }

        return (bool) preg_match('/%\{[^}]+\}|%[a-zA-Z%_-]/', $value);
    }

    private function expandDomain(?string $value, string $baseDomain): string
    {
        $value = strtolower(trim((string) $value));

        return str_replace('%{d}', $baseDomain, $value);
    }
}
