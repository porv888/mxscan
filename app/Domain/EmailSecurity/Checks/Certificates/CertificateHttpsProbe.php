<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateProbeInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;

final class CertificateHttpsProbe implements CertificateProbeInterface
{
    public function supports(CertificateEndpoint $endpoint): bool
    {
        return in_array($endpoint->kind, [
            CertificateEndpoint::KIND_PRIMARY_HTTPS,
            CertificateEndpoint::KIND_MTA_STS_HTTPS,
        ], true);
    }

    public function probe(CertificateEndpoint $endpoint): CertificateNormalizedEvidence
    {
        $timeout = (int) config('email-security.certificates.connect_timeout_seconds', 8);
        $host = $endpoint->hostname;
        $probeTime = time();

        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $host,
                'SNI_enabled' => true,
                'SNI_server_name' => $host,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$host}:{$endpoint->port}",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx,
        );

        if (!$client) {
            $lowerError = strtolower($errstr);
            $failureCategory = str_contains($lowerError, 'certificate')
                ? 'certificate_failure'
                : (str_contains($lowerError, 'timed out') ? 'connection_timeout' : 'tls_handshake_failure');
            $probeStatus = str_contains($lowerError, 'timed out')
                ? CertificateNormalizedEvidence::PROBE_TIMEOUT
                : CertificateNormalizedEvidence::PROBE_TLS_HANDSHAKE_FAILURE;

            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: $probeStatus,
                connectionSuccess: false,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                failureCategory: $failureCategory,
                failureMessage: $errstr !== '' ? $errstr : 'HTTPS connection failed.',
            );
        }

        $params = stream_context_get_params($client);
        fclose($client);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? null;

        if (!is_array($cert)) {
            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: CertificateNormalizedEvidence::PROBE_CERTIFICATE_UNAVAILABLE,
                connectionSuccess: true,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                failureCategory: 'certificate_failure',
                failureMessage: 'Peer certificate was not captured.',
            );
        }

        $parsed = openssl_x509_parse($cert);
        if (!is_array($parsed)) {
            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: CertificateNormalizedEvidence::PROBE_CERTIFICATE_UNAVAILABLE,
                connectionSuccess: true,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                certificateChain: is_array($chain) ? $chain : [$cert],
                failureCategory: 'certificate_failure',
                failureMessage: 'Peer certificate could not be parsed.',
            );
        }

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
            probeTime: $probeTime,
            parsedCertificate: $parsed,
            certificateChain: is_array($chain) ? $chain : [$cert],
        );
    }
}
