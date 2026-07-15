<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiNativeAnalysisPayload;

final class BimiAnalysisReader
{
    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function analysis(?array $bimi): ?array
    {
        if ($bimi === null) {
            return null;
        }

        $analysis = $bimi['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function protocolStatus(?array $bimi): ?string
    {
        return self::stringFromAnalysis($bimi, 'protocol_status')
            ?? self::string($bimi, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function readinessStatus(?array $bimi): ?string
    {
        return self::stringFromAnalysis($bimi, 'readiness_status')
            ?? self::string($bimi, 'readiness_status');
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function evidenceStatus(?array $bimi): ?string
    {
        return self::stringFromAnalysis($bimi, 'evidence_status')
            ?? self::string($bimi, 'evidence_status');
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function riskStatus(?array $bimi): ?string
    {
        return self::stringFromAnalysis($bimi, 'risk_status')
            ?? self::string($bimi, 'risk_status');
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function state(?array $bimi): ?string
    {
        $analysis = self::analysis($bimi);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($bimi['ui_state'] ?? null) ? $bimi['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    public static function summary(?array $bimi): ?string
    {
        $analysis = self::analysis($bimi);

        return is_string($analysis['summary'] ?? null)
            ? $analysis['summary']
            : (is_string($bimi['summary'] ?? null) ? $bimi['summary'] : null);
    }

    /**
     * @param array<string, mixed>|null $bimi
     * @return array<string, mixed>
     */
    public static function facts(?array $bimi): array
    {
        $analysis = self::analysis($bimi) ?? [];

        return [
            'bimi_protocol_status' => $analysis['protocol_status'] ?? null,
            'bimi_readiness_status' => $analysis['readiness_status'] ?? null,
            'bimi_evidence_status' => $analysis['evidence_status'] ?? null,
            'bimi_risk_status' => $analysis['risk_status'] ?? null,
            'bimi_record_present' => in_array($analysis['protocol_status'] ?? null, [
                BimiProtocolStatus::VALID,
                BimiProtocolStatus::DECLINED,
                BimiProtocolStatus::PERMERROR,
                BimiProtocolStatus::PARTIALLY_EVALUATED,
            ], true),
            'bimi_declined' => ($analysis['protocol_status'] ?? null) === BimiProtocolStatus::DECLINED,
            'bimi_selector' => $analysis['selector']['value'] ?? null,
            'bimi_selector_source' => $analysis['selector']['source'] ?? null,
            'bimi_logo_present' => ($analysis['record']['tags']['l']['raw'] ?? null) !== null
                && ($analysis['record']['tags']['l']['raw'] ?? '') !== '',
            'bimi_logo_valid' => ($analysis['indicator']['status'] ?? null) === 'valid',
            'bimi_logo_format' => $analysis['indicator']['format'] ?? null,
            'bimi_svg_tiny_ps_valid' => $analysis['indicator']['validation']['tiny_ps_valid'] ?? null,
            'bimi_logo_bytes' => $analysis['indicator']['decompressed_bytes'] ?? null,
            'bimi_dmarc_core_eligible' => $analysis['dmarc_eligibility']['core_eligible'] ?? null,
            'bimi_mark_certificate_present' => in_array($analysis['authority_evidence']['status'] ?? null, [
                BimiEvidenceStatus::VALID,
                BimiEvidenceStatus::PARTIALLY_VALIDATED,
                BimiEvidenceStatus::INVALID,
                BimiEvidenceStatus::UNSUPPORTED,
            ], true),
            'bimi_mark_certificate_type' => $analysis['authority_evidence']['type'] ?? null,
            'bimi_mark_certificate_valid' => ($analysis['authority_evidence']['status'] ?? null) === BimiEvidenceStatus::VALID,
            'bimi_mark_certificate_expires_at' => $analysis['authority_evidence']['valid_to'] ?? null,
            'bimi_indicator_match' => $analysis['indicator_comparison']['identical'] ?? null,
            'bimi_avatar_preference' => $analysis['record']['avatar_preference'] ?? null,
            'bimi_evaluation_complete' => ($analysis['evaluation_completeness'] ?? null) === 'complete',
        ];
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $bimiInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $bimiInfo = null): array
    {
        $analysis = self::analysis($bimiInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $status = (string) ($dnsRecord['status'] ?? 'missing');
        $data = is_array($dnsRecord['data'] ?? null) ? $dnsRecord['data'] : null;
        $raw = is_array($data) ? ($data['raw_record'] ?? null) : null;

        if ($status === 'missing') {
            return [
                'version' => 'legacy-readonly',
                'protocol_status' => BimiProtocolStatus::NONE,
                'readiness_status' => BimiReadinessStatus::NOT_PARTICIPATING,
                'evidence_status' => BimiEvidenceStatus::ABSENT,
                'risk_status' => BimiRiskStatus::INFORMATIONAL,
                'state' => BimiStates::MISSING,
                'summary' => 'No BIMI record was found.',
                'record' => ['raw' => null],
                'indicator' => ['status' => 'absent'],
                'authority_evidence' => ['status' => BimiEvidenceStatus::ABSENT],
                'evaluation_completeness' => 'legacy',
            ];
        }

        $logoValid = is_array($data) ? (bool) ($data['logo_valid'] ?? false) : false;

        return [
            'version' => 'legacy-readonly',
            'protocol_status' => $logoValid ? BimiProtocolStatus::PARTIALLY_EVALUATED : BimiProtocolStatus::PARTIALLY_EVALUATED,
            'readiness_status' => $logoValid ? BimiReadinessStatus::PARTIALLY_READY : BimiReadinessStatus::NOT_READY,
            'evidence_status' => BimiEvidenceStatus::ABSENT,
            'risk_status' => BimiRiskStatus::WARNING,
            'state' => $status === 'found' ? BimiStates::WARNING : BimiStates::WARNING,
            'summary' => 'Historical scan found a BIMI record snapshot.',
            'record' => ['raw' => is_string($raw) ? $raw : null],
            'indicator' => [
                'status' => $logoValid ? 'valid' : 'invalid',
                'source_uri' => is_array($data) ? ($data['logo_url'] ?? null) : null,
            ],
            'authority_evidence' => [
                'status' => BimiEvidenceStatus::ABSENT,
                'source_uri' => is_array($data) ? ($data['authority_url'] ?? null) : null,
            ],
            'evaluation_completeness' => 'legacy',
        ];
    }

    /**
     * Reconstruct a native result from persisted result_json for monitoring (read-only).
     *
     * @param array<string, mixed>|null $bimiInfo
     */
    public static function toNativeResult(string $domain, ?array $bimiInfo): ?BimiNativeResult
    {
        $analysis = self::analysis($bimiInfo);
        if ($analysis === null) {
            return null;
        }

        return new BimiNativeResult(
            state: (string) ($analysis['state'] ?? BimiStates::UNKNOWN),
            protocolStatus: (string) ($analysis['protocol_status'] ?? BimiProtocolStatus::NONE),
            readinessStatus: (string) ($analysis['readiness_status'] ?? BimiReadinessStatus::UNKNOWN),
            evidenceStatus: (string) ($analysis['evidence_status'] ?? BimiEvidenceStatus::ABSENT),
            riskStatus: (string) ($analysis['risk_status'] ?? BimiRiskStatus::UNKNOWN),
            summary: (string) ($analysis['summary'] ?? ''),
            domain: strtolower(rtrim(trim($domain), '.')),
            recordHostname: (string) ($analysis['selector']['record_hostname'] ?? 'default._bimi.' . $domain),
            evaluationCompleteness: (string) ($analysis['evaluation_completeness'] ?? 'complete'),
            rawRecord: is_string($analysis['record']['raw'] ?? null) ? $analysis['record']['raw'] : null,
            record: is_array($analysis['record'] ?? null) ? $analysis['record'] : [],
            selector: is_array($analysis['selector'] ?? null) ? $analysis['selector'] : [],
            discovery: is_array($analysis['discovery'] ?? null) ? $analysis['discovery'] : [],
            indicator: is_array($analysis['indicator'] ?? null) ? $analysis['indicator'] : [],
            authorityEvidence: is_array($analysis['authority_evidence'] ?? null) ? $analysis['authority_evidence'] : [],
            indicatorComparison: is_array($analysis['indicator_comparison'] ?? null) ? $analysis['indicator_comparison'] : [],
            dmarcEligibility: is_array($analysis['dmarc_eligibility'] ?? null) ? $analysis['dmarc_eligibility'] : [],
            providerProfiles: is_array($analysis['provider_readiness'] ?? null) ? $analysis['provider_readiness'] : [],
            localPartEvaluation: is_array($analysis['local_part_evaluation'] ?? null) ? $analysis['local_part_evaluation'] : [],
            standardsProfile: is_array($analysis['standards_profile'] ?? null) ? $analysis['standards_profile'] : [],
            errors: is_array($analysis['errors'] ?? null) ? $analysis['errors'] : [],
            warnings: is_array($analysis['warnings'] ?? null) ? $analysis['warnings'] : [],
            resolverDiagnostics: is_array($analysis['resolver_diagnostics'] ?? null) ? $analysis['resolver_diagnostics'] : [],
        );
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    private static function stringFromAnalysis(?array $bimi, string $key): ?string
    {
        $analysis = self::analysis($bimi);

        return is_array($analysis) && is_string($analysis[$key] ?? null) ? $analysis[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $bimi
     */
    private static function string(?array $bimi, string $key): ?string
    {
        return is_array($bimi) && is_string($bimi[$key] ?? null) ? $bimi[$key] : null;
    }
}
