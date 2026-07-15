<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Support;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateRiskStatus;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStatusDeriver;
use App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;

final class CertificateAnalysisReader
{
    /**
     * @param array<string, mixed>|null $certificatesInfo
     * @return array<string, mixed>|null
     */
    public static function analysis(?array $certificatesInfo): ?array
    {
        if (!is_array($certificatesInfo)) {
            return null;
        }

        $analysis = $certificatesInfo['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     */
    public static function protocolStatus(?array $certificatesInfo): ?string
    {
        return self::stringFromAnalysis($certificatesInfo, 'analysis_status')
            ?? self::string($certificatesInfo, 'analysis_status');
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     */
    public static function state(?array $certificatesInfo): ?string
    {
        $analysis = self::analysis($certificatesInfo);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($certificatesInfo['ui_state'] ?? null) ? $certificatesInfo['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     */
    public static function summary(?array $certificatesInfo): ?string
    {
        $analysis = self::analysis($certificatesInfo);

        return is_string($analysis['summary'] ?? null)
            ? $analysis['summary']
            : (is_string($certificatesInfo['summary'] ?? null) ? $certificatesInfo['summary'] : null);
    }

    /**
     * @param array<string, mixed>|null $mtaStsInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyMtaStsEvidence(?array $mtaStsInfo): array
    {
        $analysis = is_array($mtaStsInfo) ? ($mtaStsInfo['analysis'] ?? null) : null;
        $policyHostTls = is_array($analysis) ? ($analysis['policy_host_tls'] ?? []) : [];
        $mxValidation = is_array($analysis) ? ($analysis['mx_validation'] ?? []) : [];

        $endpoints = [];
        if (is_array($policyHostTls) && $policyHostTls !== []) {
            $endpoints[] = self::legacyEndpointFromPolicyHostTls($policyHostTls);
        }

        foreach ($mxValidation as $row) {
            if (!is_array($row)) {
                continue;
            }

            $smtpTls = $row['smtp_tls'] ?? null;
            if (!is_array($smtpTls)) {
                continue;
            }

            $endpoints[] = self::legacyEndpointFromSmtpTls(
                (string) ($row['hostname'] ?? ''),
                $smtpTls,
            );
        }

        $invalid = 0;
        $warning = 0;
        $valid = 0;
        $unavailable = 0;

        foreach ($endpoints as $endpoint) {
            match ($endpoint['ui_state'] ?? CertificateStates::UNKNOWN) {
                CertificateStates::PASS => $valid++,
                CertificateStates::WARNING => $warning++,
                CertificateStates::FAIL => $invalid++,
                default => $unavailable++,
            };
        }

        $state = match (true) {
            $invalid > 0 => CertificateStates::FAIL,
            $warning > 0 => CertificateStates::WARNING,
            $valid > 0 => CertificateStates::PASS,
            default => CertificateStates::UNKNOWN,
        };

        return [
            'version' => 'legacy-mta-sts-readonly',
            'analysis_status' => $endpoints === [] ? CertificateStatusDeriver::ANALYSIS_NOT_CHECKED : CertificateStatusDeriver::ANALYSIS_PARTIAL,
            'risk_status' => $invalid > 0 ? CertificateRiskStatus::CRITICAL : ($warning > 0 ? CertificateRiskStatus::WARNING : CertificateRiskStatus::UNKNOWN),
            'state' => $state,
            'summary' => 'Historical MTA-STS scan embedded certificate evidence.',
            'counts' => [
                'endpoints_total' => count($endpoints),
                'evaluated' => count($endpoints),
                'valid' => $valid,
                'warning' => $warning,
                'invalid' => $invalid,
                'unavailable' => $unavailable,
                'expiring_soon' => $warning,
            ],
            'endpoints' => $endpoints,
            'earliest_expiry' => null,
            'evaluation_completeness' => 'legacy',
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function fromDomainExpirySnapshot(?string $expiresAt, ?int $daysRemaining = null): array
    {
        if ($expiresAt === null || $expiresAt === '') {
            return [
                'version' => 'legacy-domain-expiry',
                'analysis_status' => CertificateStatusDeriver::ANALYSIS_NOT_CHECKED,
                'risk_status' => CertificateRiskStatus::UNKNOWN,
                'state' => CertificateStates::NOT_CHECKED,
                'summary' => 'No stored certificate expiry snapshot is available.',
                'counts' => [
                    'endpoints_total' => 0,
                    'evaluated' => 0,
                    'valid' => 0,
                    'warning' => 0,
                    'invalid' => 0,
                    'unavailable' => 0,
                    'expiring_soon' => 0,
                ],
                'endpoints' => [],
                'earliest_expiry' => null,
                'evaluation_completeness' => 'legacy',
            ];
        }

        $days = $daysRemaining;
        $state = CertificateStates::PASS;
        $risk = CertificateRiskStatus::HEALTHY;

        if ($days !== null) {
            if ($days < 0) {
                $state = CertificateStates::FAIL;
                $risk = CertificateRiskStatus::CRITICAL;
            } elseif ($days <= (int) config('email-security.certificates.expiry_urgent_days', 7)) {
                $state = CertificateStates::WARNING;
                $risk = CertificateRiskStatus::WARNING;
            } elseif ($days <= (int) config('email-security.certificates.expiry_warning_days', 30)) {
                $state = CertificateStates::WARNING;
                $risk = CertificateRiskStatus::WARNING;
            }
        }

        return [
            'version' => 'legacy-domain-expiry',
            'analysis_status' => CertificateStatusDeriver::ANALYSIS_PARTIAL,
            'risk_status' => $risk,
            'state' => $state,
            'summary' => 'Historical domain expiry snapshot captured outside native certificate analysis.',
            'counts' => [
                'endpoints_total' => 1,
                'evaluated' => 1,
                'valid' => $state === CertificateStates::PASS ? 1 : 0,
                'warning' => $state === CertificateStates::WARNING ? 1 : 0,
                'invalid' => $state === CertificateStates::FAIL ? 1 : 0,
                'unavailable' => 0,
                'expiring_soon' => $state === CertificateStates::WARNING ? 1 : 0,
            ],
            'endpoints' => [[
                'endpoint_key' => CertificateEndpoint::KIND_PRIMARY_HTTPS,
                'endpoint_type' => CertificateEndpoint::KIND_PRIMARY_HTTPS,
                'hostname' => null,
                'port' => CertificateEndpoint::PORT_HTTPS,
                'transport' => CertificateEndpoint::TRANSPORT_HTTPS,
                'certificate_status' => $state === CertificateStates::FAIL
                    ? CertificateEndpointEvaluation::CERTIFICATE_EXPIRED
                    : ($state === CertificateStates::WARNING
                        ? CertificateEndpointEvaluation::CERTIFICATE_WARNING
                        : CertificateEndpointEvaluation::CERTIFICATE_VALID),
                'ui_state' => $state,
                'valid_to' => $expiresAt,
                'days_until_expiry' => $days,
                'evidence_source' => 'domain_expiry_snapshot',
            ]],
            'earliest_expiry' => [
                'endpoint_key' => CertificateEndpoint::KIND_PRIMARY_HTTPS,
                'expires_at' => $expiresAt,
                'days_remaining' => $days,
            ],
            'evaluation_completeness' => 'legacy',
        ];
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     * @return array<string, mixed>
     */
    public static function resolvedAnalysis(?array $certificatesInfo): array
    {
        return self::analysis($certificatesInfo) ?? [
            'version' => CertificateNativeAnalysisPayload::VERSION,
            'analysis_status' => CertificateStatusDeriver::ANALYSIS_NOT_CHECKED,
            'risk_status' => CertificateRiskStatus::UNKNOWN,
            'state' => CertificateStates::NOT_CHECKED,
            'counts' => [
                'endpoints_total' => 0,
                'evaluated' => 0,
                'valid' => 0,
                'warning' => 0,
                'invalid' => 0,
                'unavailable' => 0,
                'expiring_soon' => 0,
            ],
            'endpoints' => [],
        ];
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     */
    public static function toNativeResult(string $domain, ?array $certificatesInfo): ?CertificateNativeResult
    {
        $analysis = self::analysis($certificatesInfo);
        if ($analysis === null) {
            return null;
        }

        $counts = is_array($analysis['counts'] ?? null) ? $analysis['counts'] : [];
        $endpoints = is_array($analysis['endpoints'] ?? null) ? $analysis['endpoints'] : [];

        return new CertificateNativeResult(
            state: (string) ($analysis['state'] ?? CertificateStates::UNKNOWN),
            analysisStatus: (string) ($analysis['analysis_status'] ?? CertificateStatusDeriver::ANALYSIS_NOT_CHECKED),
            riskStatus: (string) ($analysis['risk_status'] ?? CertificateRiskStatus::UNKNOWN),
            summary: (string) ($analysis['summary'] ?? 'Certificate analysis unavailable.'),
            domain: strtolower(rtrim(trim($domain), '.')),
            evaluationCompleteness: (string) ($analysis['evaluation_completeness'] ?? 'complete'),
            counts: $counts,
            endpoints: $endpoints,
            earliestExpiry: is_array($analysis['earliest_expiry'] ?? null) ? $analysis['earliest_expiry'] : null,
            errors: is_array($analysis['errors'] ?? null) ? $analysis['errors'] : [],
            warnings: is_array($analysis['warnings'] ?? null) ? $analysis['warnings'] : [],
        );
    }

    /**
     * @param array<string, mixed>|null $certificatesInfo
     * @return array<string, mixed>
     */
    public static function facts(?array $certificatesInfo): array
    {
        $analysis = self::resolvedAnalysis($certificatesInfo);
        $counts = is_array($analysis['counts'] ?? null) ? $analysis['counts'] : [];
        $endpoints = is_array($analysis['endpoints'] ?? null) ? $analysis['endpoints'] : [];
        $earliest = is_array($analysis['earliest_expiry'] ?? null) ? $analysis['earliest_expiry'] : null;

        $expiring30 = 0;
        $expiring14 = 0;
        $expiring7 = 0;
        $expired = 0;
        $hostnameMismatches = 0;
        $untrusted = 0;
        $primaryValid = null;
        $mtaStsValid = null;
        $smtpValidCount = 0;

        foreach ($endpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $days = $endpoint['days_until_expiry'] ?? null;
            if (is_int($days)) {
                if ($days < 0) {
                    $expired++;
                } elseif ($days <= 7) {
                    $expiring7++;
                } elseif ($days <= 14) {
                    $expiring14++;
                } elseif ($days <= 30) {
                    $expiring30++;
                }
            }

            if (($endpoint['hostname_match'] ?? true) === false) {
                $hostnameMismatches++;
            }

            if (($endpoint['trusted'] ?? true) === false) {
                $untrusted++;
            }

            $type = (string) ($endpoint['endpoint_type'] ?? '');
            $uiState = (string) ($endpoint['ui_state'] ?? '');
            $isValid = $uiState === CertificateStates::PASS || $uiState === CertificateStates::WARNING;

            if ($type === CertificateEndpoint::KIND_PRIMARY_HTTPS) {
                $primaryValid = $isValid;
            } elseif ($type === CertificateEndpoint::KIND_MTA_STS_HTTPS) {
                $mtaStsValid = $isValid;
            } elseif ($type === CertificateEndpoint::KIND_SMTP_MX && $isValid) {
                $smtpValidCount++;
            }
        }

        return [
            'certificates_analysis_status' => $analysis['analysis_status'] ?? null,
            'certificates_risk_status' => $analysis['risk_status'] ?? null,
            'certificates_endpoints_total' => (int) ($counts['endpoints_total'] ?? 0),
            'certificates_evaluated' => (int) ($counts['evaluated'] ?? 0),
            'certificates_valid' => (int) ($counts['valid'] ?? 0),
            'certificates_warning' => (int) ($counts['warning'] ?? 0),
            'certificates_invalid' => (int) ($counts['invalid'] ?? 0),
            'certificates_unavailable' => (int) ($counts['unavailable'] ?? 0),
            'certificates_expiring_30_days' => $expiring30,
            'certificates_expiring_14_days' => $expiring14,
            'certificates_expiring_7_days' => $expiring7,
            'certificates_expired' => $expired,
            'certificates_hostname_mismatches' => $hostnameMismatches,
            'certificates_untrusted' => $untrusted,
            'certificates_earliest_expiry' => $earliest['expires_at'] ?? null,
            'certificates_earliest_expiry_days' => $earliest['days_remaining'] ?? null,
            'certificates_primary_https_valid' => $primaryValid,
            'certificates_mta_sts_https_valid' => $mtaStsValid,
            'certificates_smtp_mx_valid_count' => $smtpValidCount,
        ];
    }

    /**
     * @param array<string, mixed> $policyHostTls
     * @return array<string, mixed>
     */
    private static function legacyEndpointFromPolicyHostTls(array $policyHostTls): array
    {
        $valid = ($policyHostTls['valid'] ?? false) === true;
        $hostnameMatch = ($policyHostTls['hostname_match'] ?? false) === true;
        $chainValid = ($policyHostTls['chain_valid'] ?? false) === true;

        $uiState = match (true) {
            !$valid || !$hostnameMatch || !$chainValid => CertificateStates::FAIL,
            default => CertificateStates::PASS,
        };

        return [
            'endpoint_key' => CertificateEndpoint::KIND_MTA_STS_HTTPS,
            'endpoint_type' => CertificateEndpoint::KIND_MTA_STS_HTTPS,
            'hostname' => null,
            'port' => CertificateEndpoint::PORT_HTTPS,
            'transport' => CertificateEndpoint::TRANSPORT_HTTPS,
            'certificate_status' => $uiState === CertificateStates::FAIL
                ? CertificateEndpointEvaluation::CERTIFICATE_INVALID
                : CertificateEndpointEvaluation::CERTIFICATE_VALID,
            'ui_state' => $uiState,
            'hostname_match' => $hostnameMatch,
            'trusted' => $chainValid,
            'valid_from' => $policyHostTls['valid_from'] ?? null,
            'valid_to' => $policyHostTls['expires_at'] ?? null,
            'days_until_expiry' => $policyHostTls['days_remaining'] ?? null,
            'issuer' => $policyHostTls['issuer'] ?? null,
            'subject' => $policyHostTls['subject'] ?? null,
            'san_dns' => is_array($policyHostTls['san'] ?? null) ? $policyHostTls['san'] : [],
            'evidence_source' => 'mta_sts_legacy',
        ];
    }

    /**
     * @param array<string, mixed> $smtpTls
     * @return array<string, mixed>
     */
    private static function legacyEndpointFromSmtpTls(string $hostname, array $smtpTls): array
    {
        $tlsSuccess = ($smtpTls['tls_negotiation_success'] ?? false) === true;
        $uiState = $tlsSuccess ? CertificateStates::PASS : CertificateStates::UNKNOWN;

        return [
            'endpoint_key' => CertificateEndpoint::KIND_SMTP_MX . ':' . $hostname,
            'endpoint_type' => CertificateEndpoint::KIND_SMTP_MX,
            'hostname' => $hostname,
            'port' => CertificateEndpoint::PORT_SMTP,
            'transport' => CertificateEndpoint::TRANSPORT_SMTP,
            'certificate_status' => $tlsSuccess
                ? CertificateEndpointEvaluation::CERTIFICATE_VALID
                : CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE,
            'ui_state' => $uiState,
            'valid_to' => $smtpTls['certificate_expires_at'] ?? null,
            'subject' => $smtpTls['certificate_subject'] ?? null,
            'san_dns' => is_array($smtpTls['certificate_sans'] ?? null) ? $smtpTls['certificate_sans'] : [],
            'evidence_source' => 'mta_sts_legacy',
            'failure_category' => $smtpTls['failure_category'] ?? null,
        ];
    }

    /**
     * @param array<string, mixed>|null $payload
     */
    private static function stringFromAnalysis(?array $payload, string $key): ?string
    {
        $analysis = self::analysis($payload);

        return is_string($analysis[$key] ?? null) ? $analysis[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $payload
     */
    private static function string(?array $payload, string $key): ?string
    {
        return is_string($payload[$key] ?? null) ? $payload[$key] : null;
    }
}
