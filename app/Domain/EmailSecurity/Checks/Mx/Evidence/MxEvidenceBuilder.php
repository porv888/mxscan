<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evidence;

use App\Domain\EmailSecurity\Checks\Mx\Discovery\MxRecordDiscovery;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxImplicitFallbackEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxNullPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordValidator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;

final class MxEvidenceBuilder
{
    public function __construct(
        private MxRecordDiscovery $discovery,
        private MxRecordNormalizer $normalizer,
        private MxRecordValidator $validator,
        private MxNullPolicyEvaluator $nullPolicyEvaluator,
        private MxImplicitFallbackEvaluator $implicitFallbackEvaluator,
        private MxTargetResolver $targetResolver,
        private MxStatusDeriver $statusDeriver,
    ) {
    }

    public function build(string $domain): MxNativeResult
    {
        $domain = $this->normalizer->normalizeDomain($domain);
        $discovery = $this->discovery->discover($domain);
        $errors = [];
        $warnings = [];
        $resolverDiagnostics = $discovery->resolverDiagnostics;

        if ($discovery->hasDnsFailure()) {
            $status = $this->statusDeriver->derive($discovery, [
                'published' => false,
                'valid' => false,
            ], [
                'evaluated' => false,
                'active' => false,
            ], [], [[
                'code' => 'MX_DNS_FAILURE',
                'message' => 'Temporary DNS failure prevented MX evaluation.',
            ]]);

            return $this->nativeFromParts($domain, $discovery, $status, [], [
                'published' => false,
                'valid' => false,
            ], [
                'evaluated' => false,
                'active' => false,
                'a_addresses' => [],
                'aaaa_addresses' => [],
            ], [], $errors, $warnings, $resolverDiagnostics, 'incomplete');
        }

        if ($discovery->isMissing()) {
            $implicitFallback = $this->implicitFallbackEvaluator->evaluate($domain);
            $status = $this->statusDeriver->derive($discovery, [
                'published' => false,
                'valid' => false,
            ], $implicitFallback, [], $errors);

            return $this->nativeFromParts($domain, $discovery, $status, [], [
                'published' => false,
                'valid' => false,
            ], $implicitFallback, [], $errors, $warnings, $resolverDiagnostics, 'complete');
        }

        $normalizedRecords = $this->normalizer->normalizeRecords($discovery->rawRecords);
        $validation = $this->validator->validate($normalizedRecords);
        $errors = array_merge($errors, $validation['errors']);
        $warnings = array_merge($warnings, $validation['warnings']);
        $nullMx = $this->nullPolicyEvaluator->evaluate($validation['records']);
        $errors = array_merge($errors, $nullMx['errors']);

        if (($nullMx['valid'] ?? false) === true) {
            $status = $this->statusDeriver->derive($discovery, $nullMx, [
                'evaluated' => false,
                'active' => false,
                'a_addresses' => [],
                'aaaa_addresses' => [],
            ], [], $errors);

            return $this->nativeFromParts(
                $domain,
                $discovery,
                $status,
                [],
                ['published' => true, 'valid' => true],
                ['evaluated' => false, 'active' => false, 'a_addresses' => [], 'aaaa_addresses' => []],
                [],
                $errors,
                $warnings,
                $resolverDiagnostics,
                'complete',
            );
        }

        if (($nullMx['mixed'] ?? false) === true || !$validation['valid']) {
            $status = $this->statusDeriver->derive($discovery, $nullMx, [
                'evaluated' => false,
                'active' => false,
                'a_addresses' => [],
                'aaaa_addresses' => [],
            ], [], $errors);

            return $this->nativeFromParts(
                $domain,
                $discovery,
                $status,
                [],
                ['published' => $nullMx['published'], 'valid' => false],
                ['evaluated' => false, 'active' => false, 'a_addresses' => [], 'aaaa_addresses' => []],
                [],
                $errors,
                $warnings,
                $resolverDiagnostics,
                'complete',
            );
        }

        $targets = [];
        foreach ($validation['records'] as $record) {
            $targets[] = $this->targetResolver->resolve($record);
        }

        $this->appendPreferenceWarnings($validation['records'], $warnings);
        $implicitFallback = [
            'evaluated' => false,
            'active' => false,
            'a_addresses' => [],
            'aaaa_addresses' => [],
        ];
        $status = $this->statusDeriver->derive($discovery, [
            'published' => false,
            'valid' => false,
        ], $implicitFallback, $targets, $errors);

        return $this->nativeFromParts(
            $domain,
            $discovery,
            $status,
            $targets,
            ['published' => false, 'valid' => false],
            $implicitFallback,
            $this->preferenceGroups($targets),
            $errors,
            $warnings,
            $resolverDiagnostics,
            'complete',
        );
    }

    /**
     * @param list<array<string, mixed>> $records
     * @param list<array{code: string, message: string}> $warnings
     */
    private function appendPreferenceWarnings(array $records, array &$warnings): void
    {
        $byHost = [];
        foreach ($records as $record) {
            $host = (string) ($record['normalized_exchange'] ?? '');
            $byHost[$host][] = (int) ($record['preference'] ?? 0);
        }

        foreach ($byHost as $host => $preferences) {
            if (count($preferences) > 1 && count(array_unique($preferences)) > 1) {
                $warnings[] = [
                    'code' => 'CONFLICTING_MX_PREFERENCES',
                    'message' => "The hostname {$host} is published with conflicting MX preferences.",
                ];
            }
        }
    }

    /**
     * @param list<array<string, mixed>> $targets
     * @return list<array{preference: int, targets: list<string>}>
     */
    private function preferenceGroups(array $targets): array
    {
        $groups = [];
        foreach ($targets as $target) {
            $preference = (int) ($target['preference'] ?? 0);
            $groups[$preference][] = (string) ($target['normalized_hostname'] ?? '');
        }

        ksort($groups);

        return array_values(array_map(
            fn (int $preference, array $hosts) => [
                'preference' => $preference,
                'targets' => array_values($hosts),
            ],
            array_keys($groups),
            $groups,
        ));
    }

    /**
     * @param list<array<string, mixed>> $targets
     * @param list<array{preference: int, targets: list<string>}> $preferenceGroups
     * @param array<string, mixed> $nullMx
     * @param array<string, mixed> $implicitFallback
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    private function nativeFromParts(
        string $domain,
        \App\Domain\EmailSecurity\Checks\Mx\Discovery\MxDiscoveryResult $discovery,
        array $status,
        array $targets,
        array $nullMx,
        array $implicitFallback,
        array $preferenceGroups,
        array $errors,
        array $warnings,
        array $resolverDiagnostics,
        string $evaluationCompleteness,
    ): MxNativeResult {
        $usableTargets = count(array_filter(
            $targets,
            fn (array $target) => in_array($target['status'] ?? '', [
                MxTargetResolver::STATUS_USABLE,
                MxTargetResolver::STATUS_USABLE_WITH_WARNINGS,
                MxTargetResolver::STATUS_PARTIALLY_RESOLVED,
            ], true),
        ));
        $invalidTargets = count($targets) - $usableTargets;

        return new MxNativeResult(
            state: $status['state'],
            protocolStatus: $status['protocol_status'],
            riskStatus: $status['risk_status'],
            summary: $status['summary'],
            domain: $domain,
            serviceMode: $status['service_mode'],
            dnsStatus: $discovery->dnsStatus(),
            recordsTotal: count($discovery->rawRecords),
            usableTargets: $usableTargets,
            invalidTargets: $invalidTargets,
            nullMx: [
                'published' => (bool) ($nullMx['published'] ?? false),
                'valid' => (bool) ($nullMx['valid'] ?? false),
            ],
            implicitFallback: [
                'evaluated' => (bool) ($implicitFallback['evaluated'] ?? false),
                'active' => (bool) ($implicitFallback['active'] ?? false),
                'reason' => $implicitFallback['reason'] ?? null,
                'a_addresses' => $implicitFallback['a_addresses'] ?? [],
                'aaaa_addresses' => $implicitFallback['aaaa_addresses'] ?? [],
                'usable_address_count' => $implicitFallback['usable_address_count'] ?? 0,
                'invalid_address_count' => $implicitFallback['invalid_address_count'] ?? 0,
            ],
            preferenceGroups: $preferenceGroups,
            targets: $targets,
            evaluationCompleteness: $evaluationCompleteness,
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: $resolverDiagnostics,
        );
    }
}
