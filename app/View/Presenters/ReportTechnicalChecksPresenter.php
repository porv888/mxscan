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
            $items = $this->mapItems($auth['items'] ?? [], $firstOpenId);
            $groups[] = [
                'label' => 'Authentication',
                'icon' => $this->iconForGroup('Authentication'),
                'summary' => $this->categorySummary($items),
                'items' => $items,
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
        $groups[] = [
            'label' => 'Mail infrastructure',
            'icon' => $this->iconForGroup('Mail infrastructure'),
            'summary' => $this->categorySummary($infraItems),
            'items' => $infraItems,
        ];

        $transportItems = [];
        $transport = $byLabel->get('Transport security');
        if ($transport) {
            $transportItems = $this->mapItems($transport['items'] ?? [], $firstOpenId);
        }
        $transportItems[] = $this->sslRow($firstOpenId);
        $groups[] = [
            'label' => 'Transport security',
            'icon' => $this->iconForGroup('Transport security'),
            'summary' => $this->categorySummary($transportItems),
            'items' => $transportItems,
        ];

        $branding = $byLabel->get('Optional branding');
        if ($branding) {
            $items = $this->mapItems($branding['items'] ?? [], $firstOpenId);
            $groups[] = [
                'label' => 'Optional branding',
                'icon' => $this->iconForGroup('Optional branding'),
                'summary' => $this->categorySummary($items),
                'items' => $items,
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
            'metadata' => $this->metadataForDetail($detail, $key),
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
            'metadata' => $usable ? $this->blacklistHits . '/' . $this->blacklistTotal . ' listed' : null,
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
            'metadata' => $days === null ? null : $days . ' days',
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

    /**
     * @param list<array<string, mixed>> $items
     * @return array{configured: int, attention: int, total: int, summary: string, statusVariant: string, statusLabel: string}
     */
    public function categorySummary(array $items): array
    {
        $configured = 0;
        $attention = 0;

        foreach ($items as $item) {
            $variant = $item['badgeVariant'] ?? 'neutral';
            if ($variant === 'success') {
                $configured++;
            } elseif (in_array($variant, ['warning', 'danger'], true)) {
                $attention++;
            }
        }

        $total = count($items);
        $parts = [];

        if ($configured > 0) {
            $parts[] = $configured . ' configured';
        }
        if ($attention > 0) {
            $parts[] = $attention . ' need attention';
        }
        if ($parts === []) {
            $parts[] = $total . ' check' . ($total === 1 ? '' : 's');
        }

        $worstVariant = collect($items)->pluck('badgeVariant')->contains('danger')
            ? 'danger'
            : (collect($items)->pluck('badgeVariant')->contains('warning') ? 'warning' : 'success');

        $statusLabel = match ($worstVariant) {
            'danger' => 'Issues found',
            'warning' => 'Review needed',
            default => 'Healthy',
        };

        return [
            'configured' => $configured,
            'attention' => $attention,
            'total' => $total,
            'summary' => implode(' · ', $parts),
            'statusVariant' => $worstVariant === 'success' && $attention === 0 ? 'success' : $worstVariant,
            'statusLabel' => $statusLabel,
        ];
    }

    protected function iconForGroup(string $label): string
    {
        return match ($label) {
            'Authentication' => 'shield',
            'Mail infrastructure' => 'server',
            'Transport security' => 'lock',
            'Optional branding' => 'image',
            default => 'folder',
        };
    }

    /**
     * @param array<string, mixed> $detail
     */
    protected function metadataForDetail(array $detail, string $key): ?string
    {
        if ($key === 'renewal' && isset($detail['domainDays'])) {
            return (string) $detail['domainDays'] . ' days';
        }

        if ($key === 'ssl' && isset($detail['sslDays'])) {
            return $detail['sslDays'] === null ? null : (string) $detail['sslDays'] . ' days';
        }

        if ($key === 'spf' && isset($detail['lookupCount'], $detail['lookupMax'])) {
            return $detail['lookupCount'] . '/' . $detail['lookupMax'] . ' lookups';
        }

        if ($key === 'blacklist' && isset($detail['hits'], $detail['total'])) {
            return $detail['hits'] . '/' . $detail['total'] . ' listed';
        }

        if (!empty($detail['chips'][0] ?? null)) {
            return (string) $detail['chips'][0];
        }

        return null;
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
