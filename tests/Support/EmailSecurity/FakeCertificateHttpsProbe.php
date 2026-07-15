<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateProbeInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;

final class FakeCertificateHttpsProbe implements CertificateProbeInterface
{
    private const VALID_FROM = 1784073591; // 2026-07-14T03:59:51+00:00
    private const VALID_TO = 1791849591; // 2026-10-13T03:59:51+00:00
    private const PROBE_TIME = 1784073631; // 2026-07-14T04:00:31+00:00

    public function supports(CertificateEndpoint $endpoint): bool
    {
        return in_array($endpoint->kind, [
            CertificateEndpoint::KIND_PRIMARY_HTTPS,
            CertificateEndpoint::KIND_MTA_STS_HTTPS,
        ], true);
    }

    public function probe(CertificateEndpoint $endpoint): CertificateNormalizedEvidence
    {
        $host = $endpoint->hostname;

        return new CertificateNormalizedEvidence(
            endpointKey: $endpoint->endpointKey,
            endpointKind: $endpoint->kind,
            hostname: $host,
            port: $endpoint->port,
            transport: $endpoint->transport,
            evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
            probeStatus: CertificateNormalizedEvidence::PROBE_SUCCESS,
            connectionSuccess: true,
            reused: false,
            sourceModule: 'certificates',
            probeTime: self::PROBE_TIME,
            parsedCertificate: [
                'subject' => ['CN' => $host],
                'issuer' => ['CN' => 'Test CA'],
                'validFrom_time_t' => self::VALID_FROM,
                'validTo_time_t' => self::VALID_TO,
                'extensions' => [
                    'subjectAltName' => 'DNS:' . $host,
                ],
            ],
        );
    }
}
