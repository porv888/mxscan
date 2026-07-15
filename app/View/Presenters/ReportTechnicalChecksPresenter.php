<?php

namespace App\View\Presenters;

use App\Models\Domain;

/**
 * Accordion-row presentation for technical checks on the scan report page.
 *
 * MX target rows are rendered from native analysis via {@see DnsSectionPresenter::mxDetail()}.
 */
class ReportTechnicalChecksPresenter
{
    public function __construct(
        protected DnsSectionPresenter $dns,
        protected Domain $domain,
        protected int $blacklistHits = 0,
        protected int $blacklistTotal = 0,
        protected ?int $domainDays = null,
        protected ?int $sslDays = null,
        protected bool $blacklistEnabled = true,
        protected ?array $certificatesInfo = null,
        protected ?array $mtaStsInfo = null,
    ) {
    }

    /**
     * @return list<array{label: string, items: list<array<string, mixed>>}>
     */
    public function groups(): array
    {
        $firstOpenId = $this->firstOpenRowId();
        $byLabel = collect($this->dns->detailGroups())->keyBy('label');

        $groups = [];

        $auth = $byLabel->get('Authentication');
        if ($auth) {
            $groups[] = [
                'label' => 'Authentication',
                'items' => $this->mapItems($auth['items'] ?? [], $firstOpenId),
            ];
        }

        $infraItems = [];
        $routing = $byLabel->get('Mail routing & reporting');
        if ($routing) {
            $infraItems = array_merge($infraItems, $this->mapItems($routing['items'] ?? [], $firstOpenId));
        }
        if ($this->blacklistEnabled) {
            $infraItems[] = $this->blacklistRow($firstOpenId);
        }
        $infraItems[] = $this->renewalRow($firstOpenId);
        $groups[] = ['label' => 'Mail infrastructure', 'items' => $infraItems];

        $transportItems = [];
        $transport = $byLabel->get('Transport security');
        if ($transport) {
            $transportItems = $this->mapItems($transport['items'] ?? [], $firstOpenId);
        }
        $transportItems[] = $this->sslRow($firstOpenId);
        $groups[] = ['label' => 'Transport security', 'items' => $transportItems];

        $branding = $byLabel->get('Optional branding');
        if ($branding) {
            $groups[] = [
                'label' => 'Optional branding',
                'items' => $this->mapItems($branding['items'] ?? [], $firstOpenId),
            ];
        }

        return $groups;
    }

    /**
     * @param list<array<string, mixed>> $items
     * @return list<array<string, mixed>>
     */
    protected function mapItems(array $items, ?string $firstOpenId): array
    {
        return array_map(
            fn (array $detail) => $this->mapDetailToRow($detail, $firstOpenId),
            $items
        );
    }

    protected function firstOpenRowId(): ?string
    {
        foreach ($this->dns->detailGroups() as $group) {
            foreach ($group['items'] as $detail) {
                if (($detail['open'] ?? false) === true) {
                    return 'tech-' . ($detail['key'] ?? 'item');
                }
            }
        }

        if ($this->blacklistHits > 0) {
            return 'tech-blacklist';
        }

        return null;
    }

    /**
     * @param array<string, mixed> $detail
     * @return array<string, mixed>
     */
    protected function mapDetailToRow(array $detail, ?string $firstOpenId): array
    {
        $key = $detail['key'] ?? 'item';
        $rowId = 'tech-' . $key;

        $action = $detail['primaryAction'] ?? null;
        $result = $detail['explanation'] ?? '';

        if ($key === 'dmarc_reports') {
            $result = match ($detail['badgeLabel'] ?? '') {
                'Active' => 'Reports collecting',
                'Relink required' => 'Reporting not linked',
                'Waiting' => 'Waiting for first report',
                default => 'Setup required',
            };
            if ($action === null && !empty($detail['visibilityUrl'])) {
                $action = ['label' => 'Open visibility', 'href' => $detail['visibilityUrl']];
            }
        }

        if ($key === 'spf' && ($detail['badgeLabel'] ?? '') === 'Missing') {
            $action = $action ?? ['label' => 'Add record', 'href' => '#what-to-fix'];
        }

        return [
            'id' => $rowId,
            'key' => $key,
            'icon' => $this->iconForKey($key),
            'label' => $detail['label'] ?? ucfirst($key),
            'badgeVariant' => $detail['badgeVariant'] ?? 'neutral',
            'badgeLabel' => $detail['badgeLabel'] ?? 'Unknown',
            'result' => $result,
            'action' => $action,
            'open' => $rowId === $firstOpenId,
            'detail' => $detail,
            'help' => ($this->dns->recordHelp())[$detail['helpKey'] ?? $key] ?? null,
        ];
    }

    protected function blacklistRow(?string $firstOpenId): array
    {
        $listed = $this->blacklistHits > 0;
        $usable = $this->blacklistTotal > 0;

        return [
            'id' => 'tech-blacklist',
            'key' => 'blacklist',
            'icon' => 'ban',
            'label' => 'Blacklist',
            'badgeVariant' => $listed ? 'danger' : ($usable ? 'success' : 'info'),
            'badgeLabel' => $listed ? 'Listed' : ($usable ? 'Clean' : 'Not scanned'),
            'result' => $usable
                ? "Checked against {$this->blacklistTotal} usable provider results."
                : 'No usable blacklist checks completed.',
            'action' => $listed ? ['label' => 'View details', 'href' => '#what-to-fix'] : null,
            'open' => 'tech-blacklist' === $firstOpenId,
            'detail' => ['type' => 'blacklist', 'hits' => $this->blacklistHits, 'total' => $this->blacklistTotal],
            'help' => null,
        ];
    }

    protected function renewalRow(?string $firstOpenId): array
    {
        $days = $this->domainDays;
        $variant = $days === null ? 'neutral' : ($days < 7 ? 'danger' : ($days < 30 ? 'warning' : 'success'));

        return [
            'id' => 'tech-renewal',
            'key' => 'renewal',
            'icon' => 'calendar',
            'label' => 'Domain renewal',
            'badgeVariant' => $variant,
            'badgeLabel' => $days === null ? 'Unknown' : ($days . ' days'),
            'result' => $this->domain->domain_expires_at
                ? 'Expires ' . \Carbon\Carbon::parse($this->domain->domain_expires_at)->toFormattedDateString()
                : 'Expiry date not set.',
            'action' => ['label' => 'Edit dates', 'href' => route('domains.hub.settings', $this->domain) . '#renewals'],
            'open' => false,
            'detail' => ['type' => 'renewal', 'domainDays' => $this->domainDays],
            'help' => null,
        ];
    }

    protected function sslRow(?string $firstOpenId): array
    {
        return (new CertificateSectionPresenter(
            certificatesInfo: $this->certificatesInfo,
            mtaStsInfo: $this->mtaStsInfo,
            domain: $this->domain,
        ))->sslRow($firstOpenId);
    }

    protected function iconForKey(string $key): string
    {
        return match ($key) {
            'spf' => 'shield',
            'dkim' => 'key-round',
            'dmarc' => 'shield-check',
            'dmarc_reports' => 'bar-chart-3',
            'mx' => 'mail',
            'tlsrpt' => 'activity',
            'mtasts' => 'lock',
            'bimi' => 'image',
            default => 'file-text',
        };
    }
}
