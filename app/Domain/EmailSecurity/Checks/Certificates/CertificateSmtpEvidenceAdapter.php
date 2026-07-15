<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateProbeInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;

final class CertificateSmtpEvidenceAdapter implements CertificateProbeInterface
{
    public function supports(CertificateEndpoint $endpoint): bool
    {
        return $endpoint->kind === CertificateEndpoint::KIND_SMTP_MX;
    }

    public function probe(CertificateEndpoint $endpoint): CertificateNormalizedEvidence
    {
        $timeout = (int) config('email-security.certificates.connect_timeout_seconds', 8);
        $host = $endpoint->hostname;
        $probeTime = time();
        $start = microtime(true);

        $errno = 0;
        $errstr = '';
        $socket = @fsockopen($host, $endpoint->port, $errno, $errstr, $timeout);

        if (!$socket) {
            $elapsedMs = (microtime(true) - $start) * 1000;
            $timedOut = $elapsedMs >= ($timeout * 1000);
            $failureCategory = $timedOut ? 'connection_timeout' : 'connection_refused';
            $probeStatus = $timedOut
                ? CertificateNormalizedEvidence::PROBE_TIMEOUT
                : CertificateNormalizedEvidence::PROBE_CONNECTION_FAILED;

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
                mxPriority: $endpoint->mxPriority,
                starttlsAdvertised: false,
                tlsNegotiationSuccess: false,
                failureCategory: $failureCategory,
                failureMessage: $errstr !== '' ? $errstr : 'SMTP connection failed.',
            );
        }

        stream_set_timeout($socket, $timeout);
        stream_context_set_option($socket, 'ssl', 'capture_peer_cert', true);
        stream_context_set_option($socket, 'ssl', 'capture_peer_cert_chain', true);
        stream_context_set_option($socket, 'ssl', 'verify_peer', true);
        stream_context_set_option($socket, 'ssl', 'verify_peer_name', true);
        stream_context_set_option($socket, 'ssl', 'peer_name', $host);
        stream_context_set_option($socket, 'ssl', 'SNI_enabled', true);
        stream_context_set_option($socket, 'ssl', 'SNI_server_name', $host);

        @fgets($socket, 512);
        fwrite($socket, "EHLO mxscan.me\r\n");
        $ehlo = $this->readMultiLine($socket);
        $starttlsAdvertised = (bool) preg_match('/250[- ]STARTTLS/i', $ehlo);

        if (!$starttlsAdvertised) {
            fwrite($socket, "QUIT\r\n");
            fclose($socket);

            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: CertificateNormalizedEvidence::PROBE_STARTTLS_NOT_ADVERTISED,
                connectionSuccess: true,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                mxPriority: $endpoint->mxPriority,
                starttlsAdvertised: false,
                tlsNegotiationSuccess: false,
                failureCategory: 'starttls_not_advertised',
                failureMessage: 'SMTP server did not advertise STARTTLS.',
            );
        }

        fwrite($socket, "STARTTLS\r\n");
        $tlsResponse = @fgets($socket, 512);
        if (!str_starts_with(trim((string) $tlsResponse), '220')) {
            fwrite($socket, "QUIT\r\n");
            fclose($socket);

            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: CertificateNormalizedEvidence::PROBE_TLS_HANDSHAKE_FAILURE,
                connectionSuccess: true,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                mxPriority: $endpoint->mxPriority,
                starttlsAdvertised: true,
                tlsNegotiationSuccess: false,
                failureCategory: 'tls_upgrade_failed',
                failureMessage: 'SMTP STARTTLS upgrade was rejected.',
            );
        }

        $crypto = @stream_socket_enable_crypto(
            $socket,
            true,
            STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        );

        if (!$crypto) {
            fwrite($socket, "QUIT\r\n");
            fclose($socket);

            return new CertificateNormalizedEvidence(
                endpointKey: $endpoint->endpointKey,
                endpointKind: $endpoint->kind,
                hostname: $host,
                port: $endpoint->port,
                transport: $endpoint->transport,
                evidenceSource: CertificateNormalizedEvidence::SOURCE_CERTIFICATE_PROBE,
                probeStatus: CertificateNormalizedEvidence::PROBE_TLS_HANDSHAKE_FAILURE,
                connectionSuccess: true,
                reused: false,
                sourceModule: 'certificates',
                probeTime: $probeTime,
                mxPriority: $endpoint->mxPriority,
                starttlsAdvertised: true,
                tlsNegotiationSuccess: false,
                failureCategory: 'tls_handshake_failure',
                failureMessage: 'SMTP TLS handshake failed.',
            );
        }

        $params = stream_context_get_params($socket);
        $meta = stream_get_meta_data($socket);
        $cryptoInfo = $meta['crypto'] ?? [];
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? null;
        $parsed = is_array($cert) ? openssl_x509_parse($cert) : false;

        fwrite($socket, "QUIT\r\n");
        fclose($socket);

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
                mxPriority: $endpoint->mxPriority,
                starttlsAdvertised: true,
                tlsNegotiationSuccess: true,
                tlsProtocol: isset($cryptoInfo['protocol']) ? (string) $cryptoInfo['protocol'] : null,
                certificateChain: is_array($chain) ? $chain : (is_array($cert) ? [$cert] : null),
                failureCategory: 'certificate_failure',
                failureMessage: 'SMTP peer certificate could not be parsed.',
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
            mxPriority: $endpoint->mxPriority,
            starttlsAdvertised: true,
            tlsNegotiationSuccess: true,
            tlsProtocol: isset($cryptoInfo['protocol']) ? (string) $cryptoInfo['protocol'] : null,
            parsedCertificate: $parsed,
            certificateChain: is_array($chain) ? $chain : [$cert],
        );
    }

    private function readMultiLine($socket): string
    {
        $response = '';
        for ($i = 0; $i < 50; $i++) {
            $line = @fgets($socket, 512);
            if ($line === false) {
                break;
            }
            $response .= $line;
            if (preg_match('/^\d{3} /', $line)) {
                break;
            }
        }

        return trim($response);
    }
}
