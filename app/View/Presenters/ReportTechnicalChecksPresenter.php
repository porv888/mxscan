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
        protected array $scoreBreakdown = [],
        protected array $remediation = [],
    ) {
    }

    /**
     * @return list<array{label: string, items: list<array<string, mixed>>}>
     */
    public function groups(): array
    {
        $byLabel = collect($this->dns->detailGroups())->keyBy('label');

        $groups = [];

        $auth = $byLabel->get('Authentication');
        if ($auth) {
            $items = $this->mapItems($auth['items'] ?? []);
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
            $infraItems = array_merge($infraItems, $this->mapItems($routing['items'] ?? []));
        }
        if ($this->blacklistEnabled) {
            $infraItems[] = $this->blacklistRow();
        }
        $infraItems[] = $this->renewalRow();
        $groups[] = [
            'label' => 'Mail infrastructure',
            'icon' => $this->iconForGroup('Mail infrastructure'),
            'summary' => $this->categorySummary($infraItems),
            'items' => $infraItems,
        ];

        $transportItems = [];
        $transport = $byLabel->get('Transport security');
        if ($transport) {
            $transportItems = $this->mapItems($transport['items'] ?? []);
        }
        $transportItems[] = $this->sslRow();
        $groups[] = [
            'label' => 'Transport security',
            'icon' => $this->iconForGroup('Transport security'),
            'summary' => $this->categorySummary($transportItems),
            'items' => $transportItems,
        ];

        $branding = $byLabel->get('Optional branding');
        if ($branding) {
            $items = $this->mapItems($branding['items'] ?? []);
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
    protected function mapItems(array $items): array
    {
        return array_map(
            fn (array $detail) => $this->mapDetailToRow($detail),
            $items
        );
    }

    /**
     * @param array<string, mixed> $detail
     * @return array<string, mixed>
     */
    protected function mapDetailToRow(array $detail): array
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

        if ($key === 'spf' && $this->displayBadgeLabel($key, $detail) === 'Missing') {
            $action = $action ?? ['label' => 'Add SPF', 'href' => '#what-to-fix'];
        }

        $badgeLabel = $this->displayBadgeLabel($key, $detail);
        $score = $this->scoreForKey($key);
        $optional = ($score['possible'] ?? null) === 0 || $key === 'bimi';
        $needsAttention = in_array($detail['badgeVariant'] ?? 'neutral', ['warning', 'danger'], true) && !$optional;
        $remediationKey = match ($key) {
            'dmarc_reports' => 'dmarc',
            'mtasts' => 'mta_sts',
            'tlsrpt' => 'tls_rpt',
            default => $key,
        };

        return [
            'id' => $rowId,
            'key' => $key,
            'icon' => $this->iconForKey($key),
            'label' => $detail['label'] ?? ucfirst($key),
            'badgeVariant' => $detail['badgeVariant'] ?? 'neutral',
            'badgeLabel' => $badgeLabel,
            'result' => $result,
            'metadata' => $this->metadataForDetail($detail, $key),
            'action' => $action,
            'open' => $optional ? false : (bool) ($detail['open'] ?? $detail['needsAttention'] ?? false),
            'detail' => $detail,
            'help' => ($this->dns->recordHelp())[$detail['helpKey'] ?? $key] ?? null,
            'severity' => $optional ? 'optional' : ($detail['severity'] ?? $detail['badgeVariant'] ?? 'neutral'),
            'score' => $score,
            'lostPoints' => isset($score['possible'], $score['earned'])
                ? max(0, (int) $score['possible'] - (int) $score['earned'])
                : null,
            'optional' => $optional,
            'presentationState' => $optional ? 'optional' : ($needsAttention ? 'failing' : 'passing'),
            'remediation' => $this->remediation[$remediationKey] ?? null,
        ];
    }

    protected function blacklistRow(): array
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
            'open' => $listed,
            'detail' => ['type' => 'blacklist', 'hits' => $this->blacklistHits, 'total' => $this->blacklistTotal],
            'help' => null,
            'severity' => $listed ? 'danger' : 'success',
            'presentationState' => $listed ? 'failing' : 'passing',
            'optional' => false,
            'score' => $this->scoreForKey('blacklist'),
            'lostPoints' => null,
            'remediation' => null,
        ];
    }

    protected function renewalRow(): array
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
            'open' => $days !== null && $days < 30,
            'detail' => ['type' => 'renewal', 'domainDays' => $this->domainDays],
            'help' => null,
            'severity' => $variant,
            'presentationState' => in_array($variant, ['danger', 'warning'], true) ? 'failing' : 'passing',
            'optional' => false,
            'score' => $this->scoreForKey('renewal'),
            'lostPoints' => null,
            'remediation' => null,
        ];
    }

    protected function sslRow(): array
    {
        $row = (new CertificateSectionPresenter(
            certificatesInfo: $this->certificatesInfo,
            mtaStsInfo: $this->mtaStsInfo,
            domain: $this->domain,
        ))->sslRow();

        $row['severity'] = $row['badgeVariant'] ?? 'neutral';
        $row['presentationState'] = in_array($row['badgeVariant'] ?? '', ['warning', 'danger'], true)
            ? 'failing'
            : 'passing';
        $row['optional'] = false;
        $row['score'] = $this->scoreForKey('ssl');
        $row['lostPoints'] = isset($row['score']['possible'], $row['score']['earned'])
            ? max(0, (int) $row['score']['possible'] - (int) $row['score']['earned'])
            : null;
        $row['remediation'] = $this->remediation['certificates'] ?? null;

        return $row;
    }

    /**
     * @param list<array<string, mixed>> $items
     * @return array{passing: int, attention: int, total: int, summary: string, statusVariant: string, statusLabel: string}
     */
    public function categorySummary(array $items): array
    {
        $passing = 0;
        $attention = 0;

        foreach ($items as $item) {
            if (($item['optional'] ?? false) === true) {
                continue;
            }
            $variant = $item['badgeVariant'] ?? 'neutral';
            if ($variant === 'success') {
                $passing++;
            } elseif (in_array($variant, ['warning', 'danger'], true)) {
                $attention++;
            }
        }

        $total = count($items);
        $parts = [];

        if ($passing > 0) {
            $parts[] = $passing . ' passing';
        }
        if ($attention > 0) {
            $parts[] = $attention . ' need attention';
        }
        if ($parts === []) {
            $parts[] = $total . ' check' . ($total === 1 ? '' : 's');
        }

        $scoredItems = collect($items)->reject(fn ($item) => ($item['optional'] ?? false) === true);
        $worstVariant = $scoredItems->pluck('badgeVariant')->contains('danger')
            ? 'danger'
            : ($scoredItems->pluck('badgeVariant')->contains('warning') ? 'warning' : 'success');

        $statusLabel = $attention > 0
            ? $attention . ' issue' . ($attention === 1 ? '' : 's')
            : 'All checks passing';

        return [
            'passing' => $passing,
            'attention' => $attention,
            'total' => $total,
            'summary' => implode(' · ', $parts),
            'statusVariant' => $worstVariant === 'success' && $attention === 0 ? 'success' : $worstVariant,
            'statusLabel' => $statusLabel,
        ];
    }

    /**
     * @param array<string, mixed> $detail
     */
    protected function displayBadgeLabel(string $key, array $detail): string
    {
        $label = (string) ($detail['badgeLabel'] ?? 'Unknown');
        $variant = (string) ($detail['badgeVariant'] ?? 'neutral');
        $normalized = strtolower($label);

        return match ($key) {
            'spf' => match (true) {
                $normalized === 'missing' => 'Missing',
                in_array($normalized, ['invalid', 'over limit'], true) => 'Invalid',
                in_array($normalized, ['could not evaluate', 'not checked', 'unknown'], true) => 'Unable to verify',
                $variant === 'success', $normalized === 'ok' => 'Published',
                default => $label,
            },
            'dkim' => match (true) {
                $normalized === 'published', $variant === 'success' => 'Published',
                in_array($normalized, ['missing', 'not detected'], true) => 'Not detected',
                in_array($normalized, ['unknown', 'unable to verify'], true) => 'Unable to verify',
                $normalized === 'invalid' => 'Invalid',
                default => $label,
            },
            'dmarc' => $this->dmarcBadgeLabel($detail, $label, $variant),
            'tlsrpt' => match (true) {
                $normalized === 'missing' => 'Missing',
                $normalized === 'invalid' => 'Invalid',
                $variant === 'success' => 'Configured',
                default => $label,
            },
            'ssl' => $this->sslBadgeLabel($detail, $label),
            default => $label,
        };
    }

    /**
     * @param array<string, mixed> $detail
     */
    protected function dmarcBadgeLabel(array $detail, string $label, string $variant): string
    {
        if ($variant === 'danger') {
            return match (strtolower($label)) {
                'missing' => 'Missing',
                'invalid' => 'Invalid',
                default => $label,
            };
        }

        $chip = strtolower((string) ($detail['chips'][0] ?? ''));

        return match (true) {
            str_contains($chip, 'reject') => 'Reject',
            str_contains($chip, 'quarantine') => 'Quarantine',
            str_contains($chip, 'none'), str_contains(strtolower($label), 'monitor') => 'Monitoring',
            str_contains(strtolower($label), 'reject') => 'Reject',
            str_contains(strtolower($label), 'quarantine') => 'Quarantine',
            default => $label,
        };
    }

    /**
     * @param array<string, mixed> $detail
     */
    protected function sslBadgeLabel(array $detail, string $label): string
    {
        $analysis = is_array($detail['analysis'] ?? null) ? $detail['analysis'] : [];
        $endpoints = is_array($analysis['endpoints'] ?? null) ? $analysis['endpoints'] : [];

        foreach ($endpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $verification = (string) ($endpoint['verification_state'] ?? $endpoint['certificate_status'] ?? '');
            if ($verification === 'hostname_mismatch') {
                return 'Hostname mismatch';
            }
        }

        if (strtolower($label) === 'expired' || (is_numeric(str_replace(' days', '', $label)) && (int) str_replace(' days', '', $label) < 0)) {
            return 'Expired';
        }

        if (is_numeric(str_replace(' days', '', $label))) {
            $days = (int) str_replace(' days', '', $label);
            if ($days >= 0 && $days < 30) {
                return 'Expiring';
            }
            if ($days >= 0) {
                return 'Valid';
            }
        }

        if (strtolower($label) === 'unknown') {
            return 'Unable to verify';
        }

        return $label;
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

    /**
     * @return array<string, mixed>
     */
    protected function scoreForKey(string $key): array
    {
        $aliases = [
            'tlsrpt' => ['tlsrpt', 'tls_rpt'],
            'mtasts' => ['mtasts', 'mta_sts'],
            'ssl' => ['ssl', 'certificates'],
            'dmarc_reports' => ['dmarc_reports'],
        ];
        $keys = $aliases[$key] ?? [$key];

        foreach ($this->scoreBreakdown as $row) {
            if (in_array($row['key'] ?? '', $keys, true)) {
                return $row;
            }
        }

        return $key === 'bimi'
            ? ['key' => 'bimi', 'earned' => 0, 'possible' => 0]
            : [];
    }
}
