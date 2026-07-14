<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evidence;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluationResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;

final class SpfEvidenceBuilder
{
    public function build(
        SpfDiscoveryResult $discovery,
        SpfValidationResult $validation,
        SpfEvaluationResult $evaluation,
        SpfLookupCounter $lookupCounter,
    ): SpfNativeResult {
        $rawRecord = $discovery->record;
        $normalized = $rawRecord !== null ? (preg_replace('/\s+/', ' ', trim($rawRecord)) ?: null) : null;
        $parsedTerms = array_map(fn ($term) => $term->toArray(), $validation->terms);
        $lookupCount = $lookupCounter->count();
        $state = $this->deriveState($discovery, $validation, $evaluation, $lookupCount);
        $summary = $this->deriveSummary($state, $discovery, $validation, $lookupCount);
        $flattened = $this->buildFlattened($rawRecord, $evaluation->resolvedIps, $validation->terminalPolicy);

        $errors = array_merge($validation->errors, $evaluation->errors);
        $warnings = array_merge($validation->warnings, $evaluation->warnings);

        return new SpfNativeResult(
            state: $state,
            summary: $summary,
            rawRecord: $rawRecord,
            normalizedRecord: $normalized,
            parsedTerms: $parsedTerms,
            terminalPolicy: $validation->terminalPolicy,
            lookupCount: $lookupCount,
            lookupLimit: SpfLookupCounter::LIMIT,
            lookupsRemaining: $lookupCounter->remaining(),
            voidLookupCount: $lookupCounter->voidCount(),
            lookupPaths: $lookupCounter->paths(),
            recursiveDependencies: $evaluation->dependencies,
            resolvedIps: $evaluation->resolvedIps,
            flattenedRecord: $flattened,
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: $evaluation->diagnostics,
            discovery: [
                'source' => $discovery->source,
                'domain' => $discovery->domain,
                'txt_evidence' => $discovery->txtEvidence,
                'multiple_records' => $discovery->multipleRecords,
                'dns_failure' => $discovery->dnsFailure,
            ],
        );
    }

    private function deriveState(
        SpfDiscoveryResult $discovery,
        SpfValidationResult $validation,
        SpfEvaluationResult $evaluation,
        int $lookupCount,
    ): string {
        if ($discovery->hasDnsFailure()) {
            return SpfStates::UNKNOWN;
        }
        if ($discovery->isMissing()) {
            return SpfStates::MISSING;
        }
        if ($discovery->multipleRecords || $validation->hasHardErrors() || $evaluation->lookupLimitExceeded) {
            return SpfStates::FAIL;
        }
        if ($lookupCount >= 10 || $this->hasCode($validation->errors, 'PLUS_ALL') || $this->hasCode($evaluation->errors, 'VOID_LOOKUP_LIMIT')) {
            return SpfStates::FAIL;
        }
        if ($lookupCount >= 7 || $this->hasCode($validation->warnings, 'DEPRECATED_PTR') || $this->hasCode($validation->warnings, 'MISSING_TERMINAL_ALL')) {
            return SpfStates::WARNING;
        }

        return SpfStates::PASS;
    }

    private function deriveSummary(string $state, SpfDiscoveryResult $discovery, SpfValidationResult $validation, int $lookupCount): string
    {
        return match ($state) {
            SpfStates::MISSING => 'No SPF record found.',
            SpfStates::UNKNOWN => 'SPF record discovery failed due to DNS resolver error.',
            SpfStates::FAIL => $discovery->multipleRecords
                ? 'Multiple SPF records were found.'
                : ($lookupCount >= 10
                    ? 'SPF exceeds the 10-lookup limit.'
                    : ($this->hasCode($validation->errors, 'PLUS_ALL')
                        ? 'SPF uses +all which allows any sender.'
                        : 'SPF record failed validation.')),
            SpfStates::WARNING => "SPF is valid but uses {$lookupCount} of 10 DNS lookups.",
            default => 'SPF record is valid and within DNS lookup limits.',
        };
    }

    /**
     * @param list<string> $resolvedIps
     * @param ?array{qualifier: string} $terminalPolicy
     */
    private function buildFlattened(?string $rawRecord, array $resolvedIps, ?array $terminalPolicy): ?string
    {
        if ($rawRecord === null) {
            return null;
        }

        $qualifier = $terminalPolicy['qualifier'] ?? '-';
        $all = $qualifier . 'all';

        if ($resolvedIps === []) {
            return "v=spf1 {$all}";
        }

        $ipv4 = [];
        $ipv6 = [];
        foreach (array_unique($resolvedIps) as $ip) {
            $ipPart = explode('/', (string) $ip)[0];
            if (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4[] = "ip4:{$ip}";
            } elseif (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6[] = "ip6:{$ip}";
            }
        }
        sort($ipv4);
        sort($ipv6);

        return 'v=spf1 ' . implode(' ', array_merge($ipv4, $ipv6)) . ' ' . $all;
    }

    /**
     * @param list<array{code: string}> $items
     */
    private function hasCode(array $items, string $code): bool
    {
        foreach ($items as $item) {
            if (($item['code'] ?? '') === $code) {
                return true;
            }
        }

        return false;
    }
}
