<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\DTO;

final class CertificateNormalizedEvidence
{
    public const SOURCE_MTA_STS_NATIVE = 'mta_sts_native';
    public const SOURCE_MX_NATIVE = 'mx_native';
    public const SOURCE_CERTIFICATE_PROBE = 'certificate_probe';
    public const SOURCE_PROBE_COORDINATOR = 'probe_coordinator';

    public const PROBE_SUCCESS = 'success';
    public const PROBE_CONNECTION_FAILED = 'connection_failed';
    public const PROBE_TIMEOUT = 'timeout';
    public const PROBE_TLS_HANDSHAKE_FAILURE = 'tls_handshake_failure';
    public const PROBE_CERTIFICATE_UNAVAILABLE = 'certificate_unavailable';
    public const PROBE_STARTTLS_NOT_ADVERTISED = 'starttls_not_advertised';

    /**
     * @param list<\OpenSSLCertificate|resource>|null $certificateChain
     * @param array<string, mixed>|null $parsedCertificate
     */
    public function __construct(
        public readonly string $endpointKey,
        public readonly string $endpointKind,
        public readonly string $hostname,
        public readonly int $port,
        public readonly string $transport,
        public readonly string $evidenceSource,
        public readonly string $probeStatus,
        public readonly bool $connectionSuccess,
        public readonly bool $reused,
        public readonly ?string $sourceModule = null,
        public readonly ?string $sourceAnalysisVersion = null,
        public readonly ?int $probeTime = null,
        public readonly ?int $mxPriority = null,
        public readonly ?bool $starttlsAdvertised = null,
        public readonly ?bool $tlsNegotiationSuccess = null,
        public readonly ?string $tlsProtocol = null,
        public readonly ?array $parsedCertificate = null,
        public readonly ?array $certificateChain = null,
        public readonly ?string $failureCategory = null,
        public readonly ?string $failureMessage = null,
    ) {
    }
}
