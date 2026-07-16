<?php

namespace App\Services;

use App\Models\Incident;
use App\Models\Scan;
use Carbon\Carbon;
use Illuminate\Support\Collection;

class ScanTrendService
{
    /**
     * Sparse scan history for dashboard charts.
     *
     * @return array{labels: list<string>, scores: list<int>, statuses: list<string>, scan_ids: list<string>, count: int}
     */
    public function getDomainScanHistory(int $domainId, int $days = 30): array
    {
        $scans = Scan::query()
            ->where('domain_id', $domainId)
            ->where('status', 'finished')
            ->whereNotNull('score')
            ->where('finished_at', '>=', now()->subDays($days - 1)->startOfDay())
            ->orderBy('finished_at')
            ->orderBy('created_at')
            ->get(['id', 'finished_at', 'created_at', 'score', 'status']);

        return [
            'labels' => $scans->map(fn (Scan $scan) => ($scan->finished_at ?? $scan->created_at)->format('M j, H:i'))->values()->all(),
            'scores' => $scans->pluck('score')->map(fn ($score) => (int) $score)->values()->all(),
            'statuses' => $scans->pluck('status')->values()->all(),
            'scan_ids' => $scans->pluck('id')->map(fn ($id) => (string) $id)->values()->all(),
            'count' => $scans->count(),
        ];
    }

    /**
     * Average Email Security Score per day for all user domains.
     *
     * @return array{labels: list<string>, scores: list<int|null>, incident_counts: list<int>}
     */
    public function getUserTrend(int $userId, int $days = 30): array
    {
        $start = now()->subDays($days - 1)->startOfDay();

        $scans = Scan::query()
            ->where('user_id', $userId)
            ->where('status', 'finished')
            ->whereNotNull('score')
            ->where('finished_at', '>=', $start)
            ->orderBy('finished_at')
            ->get(['finished_at', 'score', 'domain_id']);

        $domainIds = \App\Models\Domain::where('user_id', $userId)->pluck('id')->all();

        return $this->buildDailySeries($scans, $start, $days, $domainIds);
    }

    /**
     * @return array{labels: list<string>, scores: list<int|null>, incident_counts: list<int>}
     */
    public function getDomainTrend(int $domainId, int $days = 30, bool $includeIncidents = true): array
    {
        $start = now()->subDays($days - 1)->startOfDay();

        $scans = Scan::query()
            ->where('domain_id', $domainId)
            ->where('status', 'finished')
            ->whereNotNull('score')
            ->where('finished_at', '>=', $start)
            ->orderBy('finished_at')
            ->get(['finished_at', 'score']);

        $domainIds = $includeIncidents ? [$domainId] : [];

        return $this->buildDailySeries($scans, $start, $days, $domainIds);
    }

    /**
     * @param  list<int>  $domainIdsForIncidents
     * @param  Collection<int, Scan>  $scans
     * @return array{labels: list<string>, scores: list<int|null>, incident_counts: list<int>}
     */
    private function buildDailySeries(Collection $scans, Carbon $start, int $days, array $domainIdsForIncidents): array
    {
        $labels = [];
        $scores = [];
        $incidentCounts = [];

        for ($i = 0; $i < $days; $i++) {
            $day = $start->copy()->addDays($i);
            $dayEnd = $day->copy()->endOfDay();
            $labels[] = $day->format('M j');

            $dayScans = $scans->filter(function ($scan) use ($day, $dayEnd) {
                $at = $scan->finished_at ?? $scan->created_at;

                return $at && $at->between($day, $dayEnd);
            });

            $scores[] = $dayScans->isNotEmpty()
                ? (int) round($dayScans->avg('score'))
                : null;

            if ($domainIdsForIncidents !== []) {
                $incidentCounts[] = Incident::query()
                    ->whereIn('domain_id', $domainIdsForIncidents)
                    ->whereBetween('occurred_at', [$day, $dayEnd])
                    ->count();
            } else {
                $incidentCounts[] = 0;
            }
        }

        return [
            'labels' => $labels,
            'scores' => $scores,
            'incident_counts' => $incidentCounts,
        ];
    }
}
