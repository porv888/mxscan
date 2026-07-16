<?php

namespace App\View\Presenters;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Models\Domain;

/**
 * Certificate health presentation for scan reports (read-only; no TLS probes or expiry math).
 */
class CertificateSectionPresenter
{
    public function __construct(
        protected ?array $certificatesInfo = null,
        protected ?array $mtaStsInfo = null,
        protected ?Domain $domain = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function resolvedAnalysis(): array
    {
        $analysis = CertificateAnalysisReader::analysis($this->certificatesInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        if ($this->mtaStsInfo !== null) {
            return CertificateAnalysisReader::fromLegacyMtaStsEvidence($this->mtaStsInfo);
        }

        if ($this->domain !== null) {
            return CertificateAnalysisReader::fromDomainExpirySnapshot(
                $this->domain->ssl_expires_at?->toIso8601String(),
                $this->domain->getDaysUntilSslExpiry(),
            );
        }

        return CertificateAnalysisReader::resolvedAnalysis(null);
    }

    public function sslDays(): ?int
    {
        $analysis = $this->resolvedAnalysis();
        $earliest = is_array($analysis['earliest_expiry'] ?? null) ? $analysis['earliest_expiry'] : null;
        if (is_int($earliest['days_remaining'] ?? null)) {
            return $earliest['days_remaining'];
        }

        foreach ($analysis['endpoints'] ?? [] as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }
            if (($endpoint['endpoint_type'] ?? '') === CertificateEndpoint::KIND_PRIMARY_HTTPS
                && is_int($endpoint['days_until_expiry'] ?? null)) {
                return $endpoint['days_until_expiry'];
            }
        }

        return $this->domain?->getDaysUntilSslExpiry();
    }

    /**
     * Privacy-filtered primary HTTPS endpoint for public reports.
     *
     * @return array<string, mixed>|null
     */
    public function publicPrimaryEndpoint(): ?array
    {
        $analysis = $this->resolvedAnalysis();

        foreach ($analysis['endpoints'] ?? [] as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }
            if (($endpoint['endpoint_type'] ?? '') !== CertificateEndpoint::KIND_PRIMARY_HTTPS) {
                continue;
            }

            return [
                'hostname' => $endpoint['hostname'] ?? ($this->domain?->domain),
                'issuer' => $endpoint['issuer'] ?? null,
                'valid_to' => $endpoint['valid_to'] ?? null,
                'days_until_expiry' => $endpoint['days_until_expiry'] ?? null,
                'ui_state' => $endpoint['ui_state'] ?? CertificateStates::UNKNOWN,
                'hostname_match' => $endpoint['hostname_match'] ?? null,
                'trusted' => $endpoint['trusted'] ?? null,
            ];
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function sslRow(): array
    {
        $analysis = $this->resolvedAnalysis();
        $days = $this->sslDays();
        $state = (string) ($analysis['state'] ?? CertificateStates::UNKNOWN);

        $variant = match ($state) {
            CertificateStates::FAIL => 'danger',
            CertificateStates::WARNING => 'warning',
            CertificateStates::PASS => 'success',
            default => 'neutral',
        };

        $badgeLabel = match (true) {
            $state === CertificateStates::UNKNOWN, $state === CertificateStates::NOT_CHECKED => 'Unable to verify',
            $days !== null && $days < 0 => 'Expired',
            $state === CertificateStates::FAIL => 'Action required',
            $state === CertificateStates::WARNING => 'Expiring soon',
            $state === CertificateStates::PASS => 'Valid',
            default => 'Unable to verify',
        };

        $earliest = is_array($analysis['earliest_expiry'] ?? null) ? $analysis['earliest_expiry'] : null;
        $expiresAt = is_string($earliest['expires_at'] ?? null)
            ? $earliest['expires_at']
            : ($this->domain?->ssl_expires_at?->toIso8601String());

        $result = is_string($analysis['summary'] ?? null) && $analysis['summary'] !== ''
            ? $analysis['summary']
            : ($expiresAt
                ? 'Certificate expires ' . \Carbon\Carbon::parse($expiresAt)->toFormattedDateString()
                : 'Certificate expiry not set.');

        return [
            'id' => 'tech-ssl',
            'key' => 'ssl',
            'icon' => 'lock',
            'label' => 'Certificate status',
            'badgeVariant' => $variant,
            'badgeLabel' => $badgeLabel,
            'result' => $result,
            'metadata' => $days === null ? null : 'Expiry: ' . $days . ' days',
            'action' => $this->domain
                ? ['label' => 'Edit dates', 'href' => route('domains.hub.settings', $this->domain) . '#renewals']
                : null,
            'open' => in_array($variant, ['danger', 'warning'], true),
            'detail' => [
                'type' => 'ssl',
                'sslDays' => $days,
                'analysis' => $analysis,
            ],
            'help' => null,
        ];
    }
}
