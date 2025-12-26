<?php

namespace App\Services\Dmarc;

use App\Models\Domain;
use App\Models\DmarcDailyStat;
use App\Models\DmarcEvent;
use App\Models\DmarcRecord;
use App\Models\DmarcSender;
use Carbon\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class DmarcAnalyticsService
{
    /**
     * Get summary stats for a domain over a time period.
     */
    public function getDomainSummary(Domain $domain, int $days = 7): array
    {
        $startDate = now()->subDays($days)->toDateString();
        $endDate = now()->toDateString();

        $stats = DmarcDailyStat::where('domain_id', $domain->id)
            ->whereBetween('date', [$startDate, $endDate])
            ->get();

        if ($stats->isEmpty()) {
            return [
                'total_volume' => 0,
                'alignment_rate' => 0,
                'dkim_pass_rate' => 0,
                'spf_pass_rate' => 0,
                'unique_senders' => 0,
                'new_senders' => 0,
                'reports_received' => 0,
                'has_data' => false,
            ];
        }

        $totalVolume = $stats->sum('total_count');
        $alignedVolume = $stats->sum('aligned_count');
        $dkimPassVolume = $stats->sum('dkim_pass_count');
        $spfPassVolume = $stats->sum('spf_pass_count');

        return [
            'total_volume' => $totalVolume,
            'alignment_rate' => $totalVolume > 0 ? round(($alignedVolume / $totalVolume) * 100, 1) : 0,
            'dkim_pass_rate' => $totalVolume > 0 ? round(($dkimPassVolume / $totalVolume) * 100, 1) : 0,
            'spf_pass_rate' => $totalVolume > 0 ? round(($spfPassVolume / $totalVolume) * 100, 1) : 0,
            'unique_senders' => $stats->max('unique_sources') ?? 0,
            'new_senders' => $stats->sum('new_sources'),
            'reports_received' => $stats->sum('report_count'),
            'has_data' => true,
        ];
    }

    /**
     * Get comparison between current period and previous period.
     */
    public function getPeriodComparison(Domain $domain, int $days = 7): array
    {
        $current = $this->getDomainSummary($domain, $days);
        $previous = $this->getDomainSummary($domain, $days * 2);

        // Adjust previous to only include the prior period
        $previousStartDate = now()->subDays($days * 2)->toDateString();
        $previousEndDate = now()->subDays($days + 1)->toDateString();

        $previousStats = DmarcDailyStat::where('domain_id', $domain->id)
            ->whereBetween('date', [$previousStartDate, $previousEndDate])
            ->get();

        $prevTotalVolume = $previousStats->sum('total_count');
        $prevAlignedVolume = $previousStats->sum('aligned_count');
        $prevDkimPassVolume = $previousStats->sum('dkim_pass_count');
        $prevSpfPassVolume = $previousStats->sum('spf_pass_count');

        $prevAlignmentRate = $prevTotalVolume > 0 ? round(($prevAlignedVolume / $prevTotalVolume) * 100, 1) : 0;
        $prevDkimPassRate = $prevTotalVolume > 0 ? round(($prevDkimPassVolume / $prevTotalVolume) * 100, 1) : 0;
        $prevSpfPassRate = $prevTotalVolume > 0 ? round(($prevSpfPassVolume / $prevTotalVolume) * 100, 1) : 0;

        return [
            'current' => $current,
            'previous' => [
                'alignment_rate' => $prevAlignmentRate,
                'dkim_pass_rate' => $prevDkimPassRate,
                'spf_pass_rate' => $prevSpfPassRate,
                'total_volume' => $prevTotalVolume,
            ],
            'changes' => [
                'alignment_rate' => round($current['alignment_rate'] - $prevAlignmentRate, 1),
                'dkim_pass_rate' => round($current['dkim_pass_rate'] - $prevDkimPassRate, 1),
                'spf_pass_rate' => round($current['spf_pass_rate'] - $prevSpfPassRate, 1),
                'volume' => $current['total_volume'] - $prevTotalVolume,
            ],
        ];
    }

    /**
     * Get daily trend data for charts.
     */
    public function getDailyTrends(Domain $domain, int $days = 30): Collection
    {
        $startDate = now()->subDays($days)->toDateString();

        return DmarcDailyStat::where('domain_id', $domain->id)
            ->where('date', '>=', $startDate)
            ->orderBy('date')
            ->get()
            ->map(function ($stat) {
                return [
                    'date' => $stat->date->format('Y-m-d'),
                    'date_label' => $stat->date->format('M j'),
                    'total_count' => $stat->total_count,
                    'alignment_rate' => $stat->alignment_rate,
                    'dkim_pass_rate' => $stat->dkim_pass_rate,
                    'spf_pass_rate' => $stat->spf_pass_rate,
                    'fail_rate' => $stat->fail_rate,
                    'new_sources' => $stat->new_sources,
                ];
            });
    }

    /**
     * Get sender inventory with filtering.
     */
    public function getSenderInventory(
        Domain $domain,
        int $days = 30,
        ?string $status = null,
        bool $newOnly = false,
        ?string $search = null,
        int $limit = 50
    ): Collection {
        $query = DmarcSender::where('domain_id', $domain->id)
            ->where('last_seen_at', '>=', now()->subDays($days));

        if ($newOnly) {
            $query->where('is_new', true);
        }

        if ($status === 'passing') {
            $query->whereRaw('(aligned_count / NULLIF(total_count, 0)) >= 0.95');
        } elseif ($status === 'failing') {
            $query->whereRaw('(aligned_count / NULLIF(total_count, 0)) < 0.80');
        } elseif ($status === 'mixed') {
            $query->whereRaw('(aligned_count / NULLIF(total_count, 0)) >= 0.80')
                  ->whereRaw('(aligned_count / NULLIF(total_count, 0)) < 0.95');
        }

        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->where('source_ip', 'like', "%{$search}%")
                  ->orWhere('header_from', 'like', "%{$search}%")
                  ->orWhere('ptr_record', 'like', "%{$search}%")
                  ->orWhere('org_name', 'like', "%{$search}%");
            });
        }

        return $query->orderByDesc('total_count')
            ->limit($limit)
            ->get()
            ->map(function ($sender) {
                return [
                    'id' => $sender->id,
                    'source_ip' => $sender->source_ip,
                    'header_from' => $sender->header_from,
                    'org_name' => $sender->org_name,
                    'ptr_record' => $sender->ptr_record,
                    'total_count' => $sender->total_count,
                    'alignment_rate' => $sender->alignment_rate,
                    'dkim_pass_rate' => $sender->dkim_pass_rate,
                    'spf_pass_rate' => $sender->spf_pass_rate,
                    'disposition_breakdown' => [
                        'none' => $sender->disposition_none,
                        'quarantine' => $sender->disposition_quarantine,
                        'reject' => $sender->disposition_reject,
                    ],
                    'first_seen_at' => $sender->first_seen_at?->format('M j, Y'),
                    'last_seen_at' => $sender->last_seen_at?->format('M j, Y'),
                    'is_new' => $sender->is_new,
                    'is_risky' => $sender->is_risky,
                    'suggested_fix' => $sender->suggested_fix,
                    'dkim_domain' => $sender->dkim_domain,
                    'dkim_selector' => $sender->dkim_selector,
                    'spf_domain' => $sender->spf_domain,
                ];
            });
    }

    /**
     * Get top failing senders.
     */
    public function getTopFailingSenders(Domain $domain, int $days = 7, int $limit = 5): Collection
    {
        return DmarcSender::where('domain_id', $domain->id)
            ->where('last_seen_at', '>=', now()->subDays($days))
            ->where('total_count', '>=', 10)
            ->whereRaw('(aligned_count / NULLIF(total_count, 0)) < 0.80')
            ->orderByRaw('(total_count - aligned_count) DESC')
            ->limit($limit)
            ->get();
    }

    /**
     * Get recent events for a domain.
     */
    public function getRecentEvents(Domain $domain, int $days = 7, int $limit = 10): Collection
    {
        return DmarcEvent::where('domain_id', $domain->id)
            ->where('event_date', '>=', now()->subDays($days)->toDateString())
            ->orderByDesc('created_at')
            ->limit($limit)
            ->get();
    }

    /**
     * Detect fail spikes for a domain.
     */
    public function detectFailSpikes(Domain $domain, float $thresholdPct = 15, int $minVolume = 100): array
    {
        $today = now()->toDateString();
        $todayStat = DmarcDailyStat::where('domain_id', $domain->id)
            ->where('date', $today)
            ->first();

        if (!$todayStat || $todayStat->total_count < $minVolume) {
            return [];
        }

        // Get 7-day average (excluding today)
        $avgStats = DmarcDailyStat::where('domain_id', $domain->id)
            ->where('date', '>=', now()->subDays(8)->toDateString())
            ->where('date', '<', $today)
            ->selectRaw('
                AVG(alignment_rate) as avg_alignment_rate,
                AVG(dkim_pass_rate) as avg_dkim_pass_rate,
                AVG(spf_pass_rate) as avg_spf_pass_rate
            ')
            ->first();

        if (!$avgStats) {
            return [];
        }

        $spikes = [];

        // Check alignment fail spike (rate dropped)
        $alignmentDrop = $avgStats->avg_alignment_rate - $todayStat->alignment_rate;
        if ($alignmentDrop >= $thresholdPct) {
            $spikes[] = [
                'type' => DmarcEvent::TYPE_ALIGNMENT_DROP,
                'previous_rate' => $avgStats->avg_alignment_rate,
                'current_rate' => $todayStat->alignment_rate,
                'change' => -$alignmentDrop,
            ];
        }

        // Check DKIM fail spike
        $dkimDrop = $avgStats->avg_dkim_pass_rate - $todayStat->dkim_pass_rate;
        if ($dkimDrop >= $thresholdPct) {
            $spikes[] = [
                'type' => DmarcEvent::TYPE_DKIM_FAIL_SPIKE,
                'previous_rate' => $avgStats->avg_dkim_pass_rate,
                'current_rate' => $todayStat->dkim_pass_rate,
                'change' => -$dkimDrop,
            ];
        }

        // Check SPF fail spike
        $spfDrop = $avgStats->avg_spf_pass_rate - $todayStat->spf_pass_rate;
        if ($spfDrop >= $thresholdPct) {
            $spikes[] = [
                'type' => DmarcEvent::TYPE_SPF_FAIL_SPIKE,
                'previous_rate' => $avgStats->avg_spf_pass_rate,
                'current_rate' => $todayStat->spf_pass_rate,
                'change' => -$spfDrop,
            ];
        }

        return $spikes;
    }

    /**
     * Get global overview across all domains for a user.
     */
    public function getGlobalOverview(int $userId): array
    {
        $domains = Domain::where('user_id', $userId)
            ->whereNotNull('dmarc_last_report_at')
            ->get();

        $domainsWithNewSenders = 0;
        $domainsWithFailSpikes = 0;
        $totalReports24h = 0;
        $overallPassRates = [];

        $domainsNeedingAttention = [];

        foreach ($domains as $domain) {
            $summary = $this->getDomainSummary($domain, 1);
            $comparison = $this->getPeriodComparison($domain, 7);

            if ($summary['new_senders'] > 0) {
                $domainsWithNewSenders++;
            }

            // Check for fail spikes
            $hasFailSpike = $comparison['changes']['alignment_rate'] <= -15;
            if ($hasFailSpike) {
                $domainsWithFailSpikes++;
            }

            $totalReports24h += $summary['reports_received'];

            if ($summary['has_data']) {
                $overallPassRates[] = $summary['alignment_rate'];
            }

            // Determine top issue
            $topIssue = null;
            if ($hasFailSpike) {
                $topIssue = 'Alignment fail spike';
            } elseif ($summary['new_senders'] > 0) {
                $topIssue = $summary['new_senders'] . ' new sender(s)';
            } elseif ($summary['alignment_rate'] < 80) {
                $topIssue = 'Low alignment rate';
            }

            if ($topIssue || $summary['alignment_rate'] < 95) {
                $domainsNeedingAttention[] = [
                    'domain' => $domain,
                    'pass_rate_24h' => $summary['alignment_rate'],
                    'change_vs_7d' => $comparison['changes']['alignment_rate'],
                    'new_senders_7d' => $this->getDomainSummary($domain, 7)['new_senders'],
                    'top_issue' => $topIssue,
                ];
            }
        }

        return [
            'domains_with_new_senders' => $domainsWithNewSenders,
            'domains_with_fail_spikes' => $domainsWithFailSpikes,
            'overall_pass_rate' => count($overallPassRates) > 0 
                ? round(array_sum($overallPassRates) / count($overallPassRates), 1) 
                : 0,
            'reports_24h' => $totalReports24h,
            'domains_needing_attention' => $domainsNeedingAttention,
            'total_domains_with_dmarc' => $domains->count(),
        ];
    }

    /**
     * Get reporting organizations breakdown.
     */
    public function getReportingOrgs(Domain $domain, int $days = 30): Collection
    {
        return DB::table('dmarc_reports')
            ->where('domain_id', $domain->id)
            ->where('date_range_begin', '>=', now()->subDays($days))
            ->select('org_name', DB::raw('COUNT(*) as report_count'), DB::raw('SUM(total_count) as total_volume'))
            ->groupBy('org_name')
            ->orderByDesc('total_volume')
            ->limit(10)
            ->get();
    }
}
