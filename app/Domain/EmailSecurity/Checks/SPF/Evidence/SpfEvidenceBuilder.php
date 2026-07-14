<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evidence;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluationResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAssessment;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;

final class SpfEvidenceBuilder
{
    public function __construct(
        private SpfStatusDeriver $statusDeriver,
        private SpfTerminalPolicyResolver $terminalPolicyResolver,
        private SpfParser $parser,
    ) {
    }

    public function build(
        SpfDiscoveryResult $discovery,
        SpfValidationResult $validation,
        SpfEvaluationResult $evaluation,
        SpfLookupCounter $lookupCounter,
        ?SpfMacroAssessment $macroAssessment = null,
    ): SpfNativeResult {
        $rawRecord = $discovery->record;
        $normalized = $rawRecord !== null ? (preg_replace('/\s+/', ' ', trim($rawRecord)) ?: null) : null;
        $parsedTerms = array_map(fn ($term) => $term->toArray(), $validation->terms);
        $lookupCount = $lookupCounter->count();
        $derived = $this->statusDeriver->derive($discovery, $validation, $evaluation, $lookupCounter, $macroAssessment);
        [$parsedTerminalPolicy, $hasTerminalAll] = $this->resolveTerminalPolicy($validation, $evaluation);
        $flattened = $this->buildFlattened($rawRecord, $evaluation->resolvedIps, $parsedTerminalPolicy);

        $errors = array_merge($validation->errors, $evaluation->errors);
        $warnings = array_merge($validation->warnings, $evaluation->warnings);
        $terminalPolicy = $this->terminalPolicyResolver->resolve(
            $parsedTerminalPolicy,
            $hasTerminalAll,
        );

        return new SpfNativeResult(
            state: $derived->state,
            protocolStatus: $derived->protocolStatus,
            riskStatus: $derived->riskStatus,
            summary: $derived->summary,
            rawRecord: $rawRecord,
            normalizedRecord: $normalized,
            parsedTerms: $parsedTerms,
            parsedTerminalPolicy: $parsedTerminalPolicy,
            terminalPolicy: $terminalPolicy,
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

    /**
     * @return array{0: ?array{qualifier: string, mechanism: string}, 1: bool}
     */
    private function resolveTerminalPolicy(SpfValidationResult $validation, SpfEvaluationResult $evaluation): array
    {
        if ($validation->hasTerminalAll) {
            return [$validation->terminalPolicy, true];
        }

        $redirectTerminal = $this->redirectTerminalPolicy($evaluation);
        if ($redirectTerminal !== null) {
            return [$redirectTerminal, true];
        }

        return [$validation->terminalPolicy, false];
    }

    /**
     * @return ?array{qualifier: string, mechanism: string}
     */
    private function redirectTerminalPolicy(SpfEvaluationResult $evaluation): ?array
    {
        foreach ($evaluation->dependencies as $dependency) {
            if (($dependency['mechanism'] ?? '') !== 'redirect') {
                continue;
            }

            $record = $dependency['record'] ?? null;
            if (!is_string($record) || trim($record) === '') {
                continue;
            }

            $domain = (string) ($dependency['domain'] ?? '');
            foreach ($this->parser->parse($record, $domain) as $term) {
                if ($term->name === 'all') {
                    return [
                        'qualifier' => $term->qualifier,
                        'mechanism' => 'all',
                    ];
                }
            }
        }

        return null;
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
}
