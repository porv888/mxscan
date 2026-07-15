<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;

final class CertificateEvidenceBuilder
{
    public function __construct(
        private MxRecordNormalizer $domainNormalizer,
        private CertificateEndpointCollector $endpointCollector,
        private CertificateEvidenceProvider $evidenceProvider,
        private CertificateStatusDeriver $statusDeriver,
    ) {
    }

    public function build(CheckContextDTO $context): CertificateNativeResult
    {
        $domain = $this->domainNormalizer->normalizeDomain($context->domainName);
        $endpoints = $this->endpointCollector->collect($context);
        $evaluations = [];
        $errors = [];
        $warnings = [];

        foreach ($endpoints as $endpoint) {
            $evaluation = $this->evidenceProvider->obtainEndpointEvaluation($context, $endpoint);
            $evaluations[] = $evaluation;
            $errors = array_merge($errors, $evaluation->errors);
            $warnings = array_merge($warnings, $evaluation->warnings);
        }

        $endpointPayloads = array_map(
            fn (CertificateEndpointEvaluation $evaluation) => $this->endpointPayload($evaluation),
            $evaluations,
        );

        $counts = $this->buildCounts($evaluations);
        $earliestExpiry = $this->resolveEarliestExpiry($endpointPayloads);
        $status = $this->statusDeriver->derive($evaluations, $errors, $warnings);

        return new CertificateNativeResult(
            state: $status['state'],
            analysisStatus: $status['analysis_status'],
            riskStatus: $status['risk_status'],
            summary: $status['summary'],
            domain: $domain,
            evaluationCompleteness: $status['evaluation_completeness'],
            counts: $counts,
            endpoints: $endpointPayloads,
            earliestExpiry: $earliestExpiry,
            errors: $errors,
            warnings: $warnings,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function endpointPayload(CertificateEndpointEvaluation $evaluation): array
    {
        $parsed = $evaluation->parsed;
        $endpoint = $evaluation->endpoint;

        return [
            'endpoint_key' => $endpoint->endpointKey,
            'endpoint_type' => $endpoint->kind,
            'hostname' => $endpoint->hostname,
            'port' => $endpoint->port,
            'transport' => $endpoint->transport,
            'mx_priority' => $endpoint->mxPriority,
            'protocol_status' => $evaluation->protocolStatus,
            'certificate_status' => $evaluation->certificateStatus,
            'ui_state' => $evaluation->uiState,
            'evidence_source' => $evaluation->evidenceSource,
            'reused' => $evaluation->reused,
            'hostname_match' => $evaluation->hostnameMatch,
            'matched_identity' => $evaluation->matchedIdentity,
            'hostname_mismatch_reason' => $evaluation->hostnameMismatchReason,
            'trusted' => $evaluation->trusted,
            'trust_status' => $evaluation->trustStatus,
            'validity_classification' => $evaluation->validityClassification,
            'valid_from' => $parsed?->validFrom,
            'valid_to' => $parsed?->validTo,
            'days_until_expiry' => $parsed?->daysUntilExpiry,
            'issuer' => $parsed?->issuer,
            'subject' => $parsed?->subject ?? $parsed?->commonName,
            'san_dns' => $parsed?->sanDns ?? [],
            'fingerprint_sha256' => $parsed?->sha256Fingerprint,
            'serial_fingerprint' => $parsed?->serialFingerprint,
            'key' => [
                'algorithm' => $parsed?->keyAlgorithm,
                'bits' => $parsed?->keyBits,
                'curve' => $parsed?->keyCurve,
            ],
            'signature_algorithm' => $parsed?->signatureAlgorithm,
            'key_strength_classification' => $evaluation->keyStrengthClassification,
            'signature_classification' => $evaluation->signatureClassification,
            'self_signed' => $parsed?->selfSigned ?? false,
            'failure_category' => $evaluation->failureCategory,
            'errors' => $evaluation->errors,
            'warnings' => $evaluation->warnings,
        ];
    }

    /**
     * @param list<CertificateEndpointEvaluation> $evaluations
     * @return array<string, int>
     */
    private function buildCounts(array $evaluations): array
    {
        $counts = [
            'endpoints_total' => count($evaluations),
            'evaluated' => 0,
            'valid' => 0,
            'warning' => 0,
            'invalid' => 0,
            'unavailable' => 0,
            'expiring_soon' => 0,
        ];

        foreach ($evaluations as $evaluation) {
            if ($evaluation->protocolStatus === CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE
                || $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE) {
                $counts['unavailable']++;
                continue;
            }

            if (in_array($evaluation->protocolStatus, [
                CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
                CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
            ], true)) {
                $counts['evaluated']++;
            }

            if ($evaluation->uiState === CertificateEndpointEvaluation::UI_PASS) {
                $counts['valid']++;
            } elseif ($evaluation->uiState === CertificateEndpointEvaluation::UI_WARNING) {
                $counts['warning']++;
                $counts['expiring_soon']++;
            } elseif ($evaluation->uiState === CertificateEndpointEvaluation::UI_FAIL) {
                $counts['invalid']++;
            }
        }

        return $counts;
    }

    /**
     * @param list<array<string, mixed>> $endpointPayloads
     * @return array<string, mixed>|null
     */
    private function resolveEarliestExpiry(array $endpointPayloads): ?array
    {
        $candidate = null;

        foreach ($endpointPayloads as $endpoint) {
            $days = $endpoint['days_until_expiry'] ?? null;
            $expiresAt = $endpoint['valid_to'] ?? null;

            if (!is_int($days) || $expiresAt === null) {
                continue;
            }

            if ($candidate === null || $days < ($candidate['days_remaining'] ?? PHP_INT_MAX)) {
                $candidate = [
                    'endpoint_key' => $endpoint['endpoint_key'] ?? null,
                    'expires_at' => $expiresAt,
                    'days_remaining' => $days,
                ];
            }
        }

        return $candidate;
    }
}
