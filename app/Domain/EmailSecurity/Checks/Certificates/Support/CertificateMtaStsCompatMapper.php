<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Support;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;

final class CertificateMtaStsCompatMapper
{
    /**
     * @return array<string, mixed>
     */
    public function toPolicyHostTls(CertificateEndpointEvaluation $evaluation): array
    {
        $parsed = $evaluation->parsed;

        return [
            'valid' => $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_VALID
                || $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_WARNING,
            'hostname_match' => $evaluation->hostnameMatch,
            'chain_valid' => $evaluation->trusted,
            'issuer' => $parsed?->issuer,
            'subject' => $parsed?->subject ?? $parsed?->commonName,
            'san' => $parsed?->sanDns ?? [],
            'valid_from' => $parsed?->validFrom,
            'expires_at' => $parsed?->validTo,
            'days_remaining' => $parsed?->daysUntilExpiry,
            'failure_category' => $evaluation->failureCategory,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toSmtpTls(CertificateEndpointEvaluation $evaluation): array
    {
        $parsed = $evaluation->parsed;
        $endpoint = $evaluation->endpoint;

        $inspectionStatus = match ($evaluation->protocolStatus) {
            CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE => 'timeout',
            CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED => 'complete',
            default => 'complete',
        };

        if ($evaluation->failureCategory === 'connection_timeout') {
            $inspectionStatus = 'timeout';
        }

        return [
            'inspection_status' => $inspectionStatus,
            'connection_success' => $evaluation->protocolStatus !== CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE
                || $evaluation->failureCategory !== 'connection_refused',
            'tls_negotiation_success' => $evaluation->parsed !== null
                && $endpoint->kind === CertificateEndpoint::KIND_SMTP_MX,
            'tls_protocol' => null,
            'certificate_subject' => $parsed?->subject ?? $parsed?->commonName,
            'certificate_sans' => $parsed?->sanDns ?? [],
            'certificate_expires_at' => $parsed?->validTo,
            'failure_category' => $evaluation->failureCategory,
        ];
    }

    /**
     * @param list<CertificateEndpointEvaluation> $evaluations
     * @return array{policy_host_tls: ?array<string, mixed>, smtp_tls_by_hostname: array<string, array<string, mixed>>}
     */
    public function mapEvaluations(array $evaluations): array
    {
        $policyHostTls = null;
        $smtpTlsByHostname = [];

        foreach ($evaluations as $evaluation) {
            if ($evaluation->endpoint->kind === CertificateEndpoint::KIND_MTA_STS_HTTPS) {
                $policyHostTls = $this->toPolicyHostTls($evaluation);
                continue;
            }

            if ($evaluation->endpoint->kind === CertificateEndpoint::KIND_SMTP_MX) {
                $smtpTlsByHostname[$evaluation->endpoint->hostname] = $this->toSmtpTls($evaluation);
            }
        }

        return [
            'policy_host_tls' => $policyHostTls,
            'smtp_tls_by_hostname' => $smtpTlsByHostname,
        ];
    }
}
