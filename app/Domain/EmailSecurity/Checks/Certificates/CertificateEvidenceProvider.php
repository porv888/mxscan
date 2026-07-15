<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateEndpointEvidenceProviderInterface;
use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateProbeInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore;
use App\Domain\EmailSecurity\Checks\MtaSts\Compatibility\MtaStsNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class CertificateEvidenceProvider
{
    /**
     * @param list<CertificateProbeInterface> $probes
     * @param list<CertificateEndpointEvidenceProviderInterface> $evidenceProviders
     */
    public function __construct(
        private CertificateEndpointCollector $endpointCollector,
        private CertificateProbeCoordinator $probeCoordinator,
        private CertificateParser $parser,
        private CertificateHostnameValidator $hostnameValidator,
        private CertificateValidityEvaluator $validityEvaluator,
        private CertificateChainValidator $chainValidator,
        private CertificateKeyInspector $keyInspector,
        private CertificateSignatureInspector $signatureInspector,
        private array $probes = [],
        private array $evidenceProviders = [],
    ) {
    }

    /**
     * @return list<CertificateEndpointEvaluation>
     */
    public function provide(CheckContextDTO $context): array
    {
        $evaluations = [];

        foreach ($this->endpointCollector->collect($context) as $endpoint) {
            $evaluations[] = $this->obtainEndpointEvaluation($context, $endpoint);
        }

        return $evaluations;
    }

    public function obtainEndpointEvaluation(
        CheckContextDTO $context,
        CertificateEndpoint $endpoint,
    ): CertificateEndpointEvaluation {
        $evidence = $this->resolveEvidence($context, $endpoint);

        return $this->evaluateEndpoint($endpoint, $evidence);
    }

    private function resolveEvidence(CheckContextDTO $context, CertificateEndpoint $endpoint): CertificateNormalizedEvidence
    {
        $registryKey = $endpoint->toRegistryKey();
        $cached = $this->probeCoordinator->get($registryKey);
        if ($cached instanceof CertificateNormalizedEvidence) {
            return $cached;
        }

        foreach ($this->evidenceProviders as $provider) {
            if ($provider->supports($endpoint)) {
                $provided = $provider->provide($context, $endpoint);
                if ($provided instanceof CertificateNormalizedEvidence) {
                    $this->probeCoordinator->register($registryKey, $provided);

                    return $provided;
                }
            }
        }

        $reused = $this->reuseNativeEvidence($context, $endpoint);
        if ($reused instanceof CertificateNormalizedEvidence) {
            $this->probeCoordinator->register($registryKey, $reused);

            return $reused;
        }

        $probe = $this->resolveProbe($endpoint);
        if ($probe instanceof CertificateProbeInterface) {
            return $this->probeCoordinator->probeIfAbsent($endpoint, $probe);
        }

        return new CertificateNormalizedEvidence(
            endpointKey: $endpoint->endpointKey,
            endpointKind: $endpoint->kind,
            hostname: $endpoint->hostname,
            port: $endpoint->port,
            transport: $endpoint->transport,
            evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
            probeStatus: CertificateNormalizedEvidence::PROBE_CONNECTION_FAILED,
            connectionSuccess: false,
            reused: false,
            mxPriority: $endpoint->mxPriority,
            failureCategory: 'unsupported_endpoint',
            failureMessage: 'No probe is available for this endpoint type.',
        );
    }

    private function reuseNativeEvidence(CheckContextDTO $context, CertificateEndpoint $endpoint): ?CertificateNormalizedEvidence
    {
        $native = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MTA_STS_RESULT] ?? null;
        if (!$native instanceof MtaStsNativeResult) {
            return null;
        }

        if ($endpoint->kind === CertificateEndpoint::KIND_MTA_STS_HTTPS) {
            return $this->evidenceFromPolicyHostTls($endpoint, $native->policyHostTls);
        }

        if ($endpoint->kind === CertificateEndpoint::KIND_SMTP_MX) {
            foreach ($native->mxValidation as $row) {
                $hostname = CertificateEndpoint::normalizeHostname((string) ($row['hostname'] ?? ''));
                if ($hostname !== $endpoint->hostname) {
                    continue;
                }

                $smtpTls = $row['smtp_tls'] ?? null;
                if (!is_array($smtpTls)) {
                    return null;
                }

                return $this->evidenceFromSmtpTls($endpoint, $smtpTls);
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $policyHostTls
     */
    private function evidenceFromPolicyHostTls(CertificateEndpoint $endpoint, array $policyHostTls): ?CertificateNormalizedEvidence
    {
        if ($policyHostTls === []) {
            return null;
        }

        $parsed = $this->buildParsedFromCompatTls($policyHostTls);

        return new CertificateNormalizedEvidence(
            endpointKey: $endpoint->endpointKey,
            endpointKind: $endpoint->kind,
            hostname: $endpoint->hostname,
            port: $endpoint->port,
            transport: $endpoint->transport,
            evidenceSource: CertificateNormalizedEvidence::SOURCE_MTA_STS_NATIVE,
            probeStatus: CertificateNormalizedEvidence::PROBE_SUCCESS,
            connectionSuccess: true,
            reused: true,
            sourceModule: 'mta_sts',
            sourceAnalysisVersion: MtaStsNativeAnalysisPayload::VERSION,
            probeTime: time(),
            parsedCertificate: $parsed,
            failureCategory: isset($policyHostTls['failure_category']) ? (string) $policyHostTls['failure_category'] : null,
        );
    }

    /**
     * @param array<string, mixed> $smtpTls
     */
    private function evidenceFromSmtpTls(CertificateEndpoint $endpoint, array $smtpTls): CertificateNormalizedEvidence
    {
        $parsed = $this->buildParsedFromCompatSmtp($smtpTls);
        $tlsNegotiationSuccess = ($smtpTls['tls_negotiation_success'] ?? false) === true;
        $connectionSuccess = ($smtpTls['connection_success'] ?? false) === true;
        $inspectionStatus = (string) ($smtpTls['inspection_status'] ?? '');

        $probeStatus = match (true) {
            $tlsNegotiationSuccess => CertificateNormalizedEvidence::PROBE_SUCCESS,
            $inspectionStatus === 'timeout' => CertificateNormalizedEvidence::PROBE_TIMEOUT,
            !$connectionSuccess => CertificateNormalizedEvidence::PROBE_CONNECTION_FAILED,
            default => CertificateNormalizedEvidence::PROBE_TLS_HANDSHAKE_FAILURE,
        };

        return new CertificateNormalizedEvidence(
            endpointKey: $endpoint->endpointKey,
            endpointKind: $endpoint->kind,
            hostname: $endpoint->hostname,
            port: $endpoint->port,
            transport: $endpoint->transport,
            evidenceSource: CertificateNormalizedEvidence::SOURCE_MTA_STS_NATIVE,
            probeStatus: $probeStatus,
            connectionSuccess: $connectionSuccess,
            reused: true,
            sourceModule: 'mta_sts',
            sourceAnalysisVersion: MtaStsNativeAnalysisPayload::VERSION,
            probeTime: time(),
            mxPriority: $endpoint->mxPriority,
            starttlsAdvertised: $connectionSuccess,
            tlsNegotiationSuccess: $tlsNegotiationSuccess,
            tlsProtocol: isset($smtpTls['tls_protocol']) ? (string) $smtpTls['tls_protocol'] : null,
            parsedCertificate: $parsed,
            failureCategory: isset($smtpTls['failure_category']) ? (string) $smtpTls['failure_category'] : null,
        );
    }

    /**
     * @param array<string, mixed> $policyHostTls
     * @return array<string, mixed>
     */
    private function buildParsedFromCompatTls(array $policyHostTls): array
    {
        $validFrom = isset($policyHostTls['valid_from']) ? strtotime((string) $policyHostTls['valid_from']) : false;
        $validTo = isset($policyHostTls['expires_at']) ? strtotime((string) $policyHostTls['expires_at']) : false;
        $san = is_array($policyHostTls['san'] ?? null) ? $policyHostTls['san'] : [];

        return [
            'subject' => ['CN' => (string) ($policyHostTls['subject'] ?? '')],
            'issuer' => ['CN' => (string) ($policyHostTls['issuer'] ?? '')],
            'validFrom_time_t' => $validFrom !== false ? $validFrom : null,
            'validTo_time_t' => $validTo !== false ? $validTo : null,
            'extensions' => [
                'subjectAltName' => implode(', ', array_map(
                    fn (string $entry) => 'DNS:' . $entry,
                    array_map('strval', $san),
                )),
            ],
        ];
    }

    /**
     * @param array<string, mixed> $smtpTls
     * @return array<string, mixed>|null
     */
    private function buildParsedFromCompatSmtp(array $smtpTls): ?array
    {
        if (($smtpTls['tls_negotiation_success'] ?? false) !== true) {
            return null;
        }

        $validTo = isset($smtpTls['certificate_expires_at']) ? strtotime((string) $smtpTls['certificate_expires_at']) : false;
        $sans = is_array($smtpTls['certificate_sans'] ?? null) ? $smtpTls['certificate_sans'] : [];

        return [
            'subject' => ['CN' => (string) ($smtpTls['certificate_subject'] ?? '')],
            'issuer' => [],
            'validTo_time_t' => $validTo !== false ? $validTo : null,
            'extensions' => [
                'subjectAltName' => implode(', ', array_map(
                    fn (string $entry) => 'DNS:' . $entry,
                    array_map('strval', $sans),
                )),
            ],
        ];
    }

    private function resolveProbe(CertificateEndpoint $endpoint): ?CertificateProbeInterface
    {
        foreach ($this->probes as $probe) {
            if ($probe->supports($endpoint)) {
                return $probe;
            }
        }

        return null;
    }

    private function evaluateEndpoint(CertificateEndpoint $endpoint, CertificateNormalizedEvidence $evidence): CertificateEndpointEvaluation
    {
        if (!$evidence->connectionSuccess) {
            return $this->unavailableEvaluation($endpoint, $evidence);
        }

        if ($endpoint->kind === CertificateEndpoint::KIND_SMTP_MX && $evidence->starttlsAdvertised === false) {
            return new CertificateEndpointEvaluation(
                endpoint: $endpoint,
                protocolStatus: CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE,
                certificateStatus: CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE,
                uiState: CertificateEndpointEvaluation::UI_UNKNOWN,
                hostnameMatch: false,
                matchedIdentity: null,
                hostnameMismatchReason: null,
                trusted: false,
                trustStatus: null,
                parsed: null,
                evidenceSource: $evidence->evidenceSource,
                reused: $evidence->reused,
                validityClassification: CertificateValidityEvaluator::STATUS_UNKNOWN,
                keyStrengthClassification: CertificateKeyInspector::CLASSIFICATION_UNAVAILABLE,
                signatureClassification: CertificateSignatureInspector::CLASSIFICATION_UNAVAILABLE,
                failureCategory: $evidence->failureCategory ?? 'starttls_not_advertised',
                errors: [],
                warnings: [[
                    'code' => 'STARTTLS_NOT_ADVERTISED',
                    'message' => 'SMTP server did not advertise STARTTLS.',
                ]],
            );
        }

        if ($evidence->parsedCertificate === null) {
            return $this->unavailableEvaluation($endpoint, $evidence);
        }

        $parsed = $this->parser->parse(
            $evidence->parsedCertificate,
            $evidence->certificateChain,
        );

        $hostnameResult = $this->hostnameValidator->validate($endpoint->hostname, $parsed);
        $validityClassification = $this->validityEvaluator->evaluate(
            $parsed->validFromTimestamp,
            $parsed->validToTimestamp,
        );
        $chainResult = $this->chainValidator->validate(
            $evidence->certificateChain,
            $endpoint->hostname,
            $parsed,
        );
        $keyResult = $this->keyInspector->inspect($parsed);
        $signatureResult = $this->signatureInspector->inspect($parsed);

        $errors = [];
        $warnings = array_merge($keyResult['warnings'], $signatureResult['warnings']);

        if (!$hostnameResult['hostname_match']) {
            $errors[] = [
                'code' => 'HOSTNAME_MISMATCH',
                'message' => $hostnameResult['mismatch_reason'] ?? 'Certificate hostname mismatch.',
            ];
        }

        if ($validityClassification === CertificateValidityEvaluator::STATUS_EXPIRED) {
            $errors[] = [
                'code' => 'CERTIFICATE_EXPIRED',
                'message' => 'Certificate is expired.',
            ];
        }

        if ($validityClassification === CertificateValidityEvaluator::STATUS_NOT_YET_VALID) {
            $errors[] = [
                'code' => 'CERTIFICATE_NOT_YET_VALID',
                'message' => 'Certificate is not yet valid.',
            ];
        }

        if (!$chainResult['trusted']) {
            $errors[] = [
                'code' => 'CERTIFICATE_UNTRUSTED',
                'message' => $chainResult['diagnostics'][0] ?? 'Certificate chain is not trusted.',
            ];
        }

        if ($this->validityEvaluator->isExpiryWarning($validityClassification)) {
            $warnings[] = [
                'code' => 'CERTIFICATE_EXPIRING',
                'message' => 'Certificate is approaching expiry.',
            ];
        }

        [$certificateStatus, $uiState, $protocolStatus] = $this->deriveStatuses(
            $validityClassification,
            $hostnameResult['hostname_match'],
            $chainResult['trusted'],
            $warnings,
            $errors,
            $evidence,
        );

        return new CertificateEndpointEvaluation(
            endpoint: $endpoint,
            protocolStatus: $protocolStatus,
            certificateStatus: $certificateStatus,
            uiState: $uiState,
            hostnameMatch: $hostnameResult['hostname_match'],
            matchedIdentity: $hostnameResult['matched_identity'],
            hostnameMismatchReason: $hostnameResult['mismatch_reason'],
            trusted: $chainResult['trusted'],
            trustStatus: $chainResult['status'],
            parsed: $parsed,
            evidenceSource: $evidence->evidenceSource,
            reused: $evidence->reused,
            validityClassification: $validityClassification,
            keyStrengthClassification: $keyResult['classification'],
            signatureClassification: $signatureResult['classification'],
            failureCategory: $evidence->failureCategory,
            errors: $errors,
            warnings: $warnings,
        );
    }

    /**
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array{code: string, message: string}> $errors
     * @return array{0: string, 1: string, 2: string}
     */
    private function deriveStatuses(
        string $validityClassification,
        bool $hostnameMatch,
        bool $trusted,
        array $warnings,
        array $errors,
        CertificateNormalizedEvidence $evidence,
    ): array {
        if ($evidence->reused && $evidence->certificateChain === null) {
            if ($errors !== []) {
                return [
                    CertificateEndpointEvaluation::CERTIFICATE_INVALID,
                    CertificateEndpointEvaluation::UI_FAIL,
                    CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
                ];
            }

            if ($warnings !== []) {
                return [
                    CertificateEndpointEvaluation::CERTIFICATE_WARNING,
                    CertificateEndpointEvaluation::UI_WARNING,
                    CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
                ];
            }

            return [
                CertificateEndpointEvaluation::CERTIFICATE_VALID,
                CertificateEndpointEvaluation::UI_PASS,
                CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
            ];
        }

        if ($validityClassification === CertificateValidityEvaluator::STATUS_EXPIRED) {
            return [
                CertificateEndpointEvaluation::CERTIFICATE_EXPIRED,
                CertificateEndpointEvaluation::UI_FAIL,
                CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            ];
        }

        if ($validityClassification === CertificateValidityEvaluator::STATUS_NOT_YET_VALID) {
            return [
                CertificateEndpointEvaluation::CERTIFICATE_NOT_YET_VALID,
                CertificateEndpointEvaluation::UI_FAIL,
                CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            ];
        }

        if (!$hostnameMatch || !$trusted) {
            return [
                CertificateEndpointEvaluation::CERTIFICATE_INVALID,
                CertificateEndpointEvaluation::UI_FAIL,
                CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            ];
        }

        if ($this->validityEvaluator->isExpiryWarning($validityClassification) || $warnings !== []) {
            return [
                CertificateEndpointEvaluation::CERTIFICATE_WARNING,
                CertificateEndpointEvaluation::UI_WARNING,
                CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            ];
        }

        return [
            CertificateEndpointEvaluation::CERTIFICATE_VALID,
            CertificateEndpointEvaluation::UI_PASS,
            CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
        ];
    }

    private function unavailableEvaluation(
        CertificateEndpoint $endpoint,
        CertificateNormalizedEvidence $evidence,
    ): CertificateEndpointEvaluation {
        return new CertificateEndpointEvaluation(
            endpoint: $endpoint,
            protocolStatus: CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE,
            certificateStatus: CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE,
            uiState: CertificateEndpointEvaluation::UI_UNKNOWN,
            hostnameMatch: false,
            matchedIdentity: null,
            hostnameMismatchReason: null,
            trusted: false,
            trustStatus: SystemCertificateTrustStore::STATUS_VALIDATION_UNAVAILABLE,
            parsed: null,
            evidenceSource: $evidence->evidenceSource,
            reused: $evidence->reused,
            validityClassification: CertificateValidityEvaluator::STATUS_UNKNOWN,
            keyStrengthClassification: CertificateKeyInspector::CLASSIFICATION_UNAVAILABLE,
            signatureClassification: CertificateSignatureInspector::CLASSIFICATION_UNAVAILABLE,
            failureCategory: $evidence->failureCategory,
            errors: $evidence->failureMessage !== null ? [[
                'code' => 'PROBE_FAILURE',
                'message' => $evidence->failureMessage,
            ]] : [],
            warnings: [],
        );
    }
}
