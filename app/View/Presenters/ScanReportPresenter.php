<?php

namespace App\View\Presenters;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\ScanReport\ScanReportStatusMapper;

/**
 * View-only presenter for the scan report page composition.
 */
class ScanReportPresenter
{
    /**
     * @param array<string, mixed> $statusCards
     * @param list<array<string, mixed>> $recommendations
     * @param array{state: string, message: ?string} $allClear
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array{labels: list<string>, scores: list<int|null>} $scoreTrend
     */
    public function __construct(
        protected Domain $domain,
        protected ?int $score,
        protected ?int $scoreDelta,
        protected array $statusCards,
        protected array $recommendations,
        protected array $allClear,
        protected array $scoreBreakdown,
        protected array $scoreTrend,
        protected int $blacklistHits = 0,
        protected int $blacklistTotal = 0,
        protected ?string $dmarcPolicy = null,
    ) {
    }

    /**
     * @return array{percent: int, label: string, supporting: string, subtitle: string}
     */
    public function scoreMeta(): array
    {
        $score = (int) ($this->score ?? 0);
        $openIssues = collect($this->coreRecommendations())
            ->whereIn('severity', ['critical', 'high'])
            ->count();

        $label = match (true) {
            $score >= 90 => 'Excellent',
            $score >= 70 => 'Good standing',
            $score >= 50 => 'Needs attention',
            default => 'Critical issues',
        };

        $supporting = match (true) {
            ($this->allClear['state'] ?? '') === 'all_clear' => 'Core email authentication checks passed.',
            $openIssues === 0 => 'Review optional improvements below.',
            $openIssues === 1 => 'One important protection requires attention.',
            default => $openIssues . ' important protections require attention.',
        };

        return [
            'percent' => max(0, min(100, $score)),
            'label' => $label,
            'supporting' => $supporting,
            'subtitle' => 'Authentication and transport-security configuration',
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    public function primaryFinding(): ?array
    {
        if (($this->allClear['state'] ?? '') === 'all_clear') {
            return [
                'severity' => 'success',
                'badge' => 'All clear',
                'title' => 'No critical fixes needed',
                'explanation' => $this->allClear['message'] ?? 'Core email authentication checks passed.',
                'impact' => null,
                'cta' => null,
                'ctaHref' => null,
                'whyHref' => null,
                'technicalTarget' => null,
            ];
        }

        $rec = $this->coreRecommendations()[0] ?? null;
        if ($rec === null) {
            return null;
        }

        return [
            'severity' => $rec['severity'] ?? 'medium',
            'badge' => ucfirst($rec['severity'] ?? 'medium'),
            'title' => $rec['title'],
            'explanation' => $rec['explanation'],
            'impact' => $this->impactForKey($rec['key'] ?? ''),
            'cta' => $rec['action'] ?? $rec['title'],
            'ctaHref' => '#what-to-fix',
            'whyHref' => '#technical-checks',
            'technicalTarget' => $this->technicalTargetForKey($rec['key'] ?? ''),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function authStripItems(): array
    {
        $spf = $this->statusCards['spf'] ?? [];
        $dkim = $this->statusCards['dkim'] ?? [];
        $dmarc = $this->statusCards['dmarc'] ?? [];
        $bl = $this->statusCards['blacklist'] ?? [];

        return [
            [
                'key' => 'spf',
                'icon' => 'shield',
                'label' => 'SPF',
                'status' => $spf['status'] ?? 'Unknown',
                'explanation' => $this->authExplanation('spf', $spf),
                'variant' => $this->variantForState($spf['state'] ?? 'unknown'),
            ],
            [
                'key' => 'dkim',
                'icon' => 'key-round',
                'label' => 'DKIM DNS',
                'status' => ($dkim['state'] ?? '') === ScanReportStatusMapper::PASS
                    ? 'Configured'
                    : ($dkim['status'] ?? 'Missing'),
                'explanation' => $this->authExplanation('dkim', $dkim),
                'variant' => $this->variantForState($dkim['state'] ?? 'unknown'),
            ],
            [
                'key' => 'dmarc',
                'icon' => 'shield-check',
                'label' => 'DMARC',
                'status' => $this->dmarcPolicy
                    ? ucfirst($this->dmarcPolicy)
                    : ($dmarc['status'] ?? 'Missing'),
                'explanation' => $this->authExplanation('dmarc', $dmarc),
                'variant' => $this->variantForState($dmarc['state'] ?? 'unknown'),
            ],
            [
                'key' => 'blacklist',
                'icon' => 'ban',
                'label' => 'Blacklist',
                'status' => $bl['label'] ?? 'Not scanned',
                'explanation' => $bl['subtext'] ?? 'Blacklist check did not run.',
                'variant' => $this->variantForState($bl['state'] ?? 'unknown'),
            ],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function coreRecommendations(): array
    {
        return collect($this->recommendations)
            ->reject(fn (array $r) => ($r['severity'] ?? '') === 'optional')
            ->values()
            ->all();
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function optionalRecommendations(): array
    {
        return collect($this->recommendations)
            ->where('severity', 'optional')
            ->values()
            ->all();
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function scoreBreakdownRows(): array
    {
        return collect($this->scoreBreakdown)
            ->filter(fn (array $row) => ($row['possible'] ?? 0) > 0)
            ->values()
            ->all();
    }

    public function scoreEarnedTotal(): int
    {
        return min(100, (int) collect($this->scoreBreakdown)->sum('earned'));
    }

    public function finishedScanCount(): int
    {
        return Scan::query()
            ->where('domain_id', $this->domain->id)
            ->where('status', 'finished')
            ->count();
    }

    public function shouldShowChart(): bool
    {
        if ($this->finishedScanCount() < 2) {
            return false;
        }

        $nonNullScores = collect($this->scoreTrend['scores'] ?? [])
            ->filter(fn ($score) => $score !== null)
            ->count();

        return $nonNullScores >= 2;
    }

    /**
     * @return array{score: int|null, date: ?string, message: string}
     */
    public function historyEmptyState(?string $scanDate): array
    {
        return [
            'score' => $this->score,
            'date' => $scanDate,
            'message' => 'Your trend will appear after another completed scan.',
        ];
    }

    public function impactForKey(string $key): ?string
    {
        return match ($key) {
            'spf_missing', 'spf_invalid' => 'Reduces spoofing and sender-authentication failures.',
            'spf_lookups' => 'Exceeding the SPF lookup limit can cause receivers to fail SPF checks.',
            'dmarc_missing' => 'Without DMARC, spoofed email using your domain is harder to stop and track.',
            'dmarc_policy', 'dmarc_alignment' => 'Weak DMARC policy reduces protection against domain impersonation.',
            'dkim_dns' => 'Missing DKIM DNS weakens DMARC authentication.',
            'blacklist' => 'Blacklist listings severely impact deliverability and sender reputation.',
            'tlsrpt' => 'TLS delivery problems may go unnoticed without reporting.',
            'mtasts' => 'Without MTA-STS, secure mail transport is easier to downgrade.',
            default => null,
        };
    }

    protected function technicalTargetForKey(string $key): ?string
    {
        return match ($key) {
            'spf_missing', 'spf_invalid', 'spf_lookups' => 'tech-spf',
            'dmarc_missing', 'dmarc_policy', 'dmarc_alignment' => 'tech-dmarc',
            'dkim_dns' => 'tech-dkim',
            'blacklist' => 'tech-blacklist',
            'tlsrpt' => 'tech-tlsrpt',
            'mtasts' => 'tech-mtasts',
            default => null,
        };
    }

    /**
     * @param array<string, mixed> $card
     */
    protected function authExplanation(string $key, array $card): string
    {
        return match ($key) {
            'spf' => match ($card['state'] ?? '') {
                ScanReportStatusMapper::MISSING => 'No SPF configuration published.',
                ScanReportStatusMapper::FAIL => $card['subtext'] ?? 'SPF configuration invalid.',
                ScanReportStatusMapper::WARNING => $card['subtext'] ?? 'SPF lookup count is elevated.',
                ScanReportStatusMapper::UNKNOWN => $card['subtext'] ?? 'SPF configuration could not be fully evaluated.',
                default => ($card['subtext'] ?? 'SPF configuration found.') !== 'Lookup count not applicable'
                    ? ($card['subtext'] ?? 'SPF configuration found.')
                    : 'SPF configuration is published.',
            },
            'dkim' => ($card['state'] ?? '') === ScanReportStatusMapper::PASS
                ? (($card['count'] ?? 0) . ' selector' . (($card['count'] ?? 0) === 1 ? '' : 's') . ' discovered.')
                : 'No DKIM selectors discovered.',
            'dmarc' => match ($card['state'] ?? '') {
                ScanReportStatusMapper::MISSING => 'No DMARC policy published.',
                ScanReportStatusMapper::WARNING => 'Policy is monitoring only.',
                default => 'Policy is active.',
            },
            default => $card['subtext'] ?? '',
        };
    }

    protected function variantForState(string $state): string
    {
        return match ($state) {
            ScanReportStatusMapper::PASS => 'success',
            ScanReportStatusMapper::WARNING => 'warning',
            ScanReportStatusMapper::FAIL, ScanReportStatusMapper::MISSING => 'danger',
            ScanReportStatusMapper::NOT_CHECKED => 'info',
            default => 'neutral',
        };
    }
}
