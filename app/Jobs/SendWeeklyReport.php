<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\ScanSnapshot;
use App\Models\ScanDelta;
use App\Models\Incident;
use App\Mail\WeeklyReportMail;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Barryvdh\DomPDF\Facade\Pdf;

class SendWeeklyReport implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct()
    {
        //
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        Log::info('Starting weekly report generation');

        $reportsSent = 0;
        $weekStart = now()->startOfWeek()->subWeek();
        $weekEnd = now()->startOfWeek()->subSecond();

        Domain::with(['user', 'scanSnapshots', 'scanDeltas', 'incidents'])
            ->whereHas('user', function ($query) {
                $query->whereHas('notificationPrefs', function ($prefQuery) {
                    $prefQuery->where('weekly_reports', true);
                });
            })
            ->chunk(50, function ($domains) use (&$reportsSent, $weekStart, $weekEnd) {
                foreach ($domains as $domain) {
                    try {
                        // Skip if user can't use weekly reports (plan-gated)
                        if (!$domain->user->canUseWeeklyReports()) {
                            continue;
                        }

                        $reportData = $this->generateReportData($domain, $weekStart, $weekEnd);
                        
                        // Skip if no activity this week
                        if ($this->shouldSkipReport($reportData)) {
                            continue;
                        }

                        $pdf = $this->generatePdf($domain, $reportData, $weekStart, $weekEnd);
                        
                        Mail::to($domain->user->email)->send(
                            new WeeklyReportMail($domain, $pdf->output(), $weekStart, $weekEnd)
                        );

                        $reportsSent++;

                        Log::info('Weekly report sent', [
                            'domain' => $domain->domain,
                            'user_email' => $domain->user->email,
                        ]);

                    } catch (\Exception $e) {
                        Log::error('Failed to send weekly report', [
                            'domain' => $domain->domain,
                            'error' => $e->getMessage(),
                        ]);
                    }
                }
            });

        Log::info('Weekly report generation completed', [
            'reports_sent' => $reportsSent,
        ]);
    }

    /**
     * Generate report data for a domain
     */
    protected function generateReportData(Domain $domain, $weekStart, $weekEnd): array
    {
        // Get snapshots from this week
        $snapshots = ScanSnapshot::where('domain_id', $domain->id)
            ->whereBetween('created_at', [$weekStart, $weekEnd])
            ->orderBy('created_at')
            ->get();

        // Get deltas from this week
        $deltas = ScanDelta::where('domain_id', $domain->id)
            ->whereBetween('created_at', [$weekStart, $weekEnd])
            ->with('snapshot')
            ->get();

        // Get incidents from this week
        $incidents = Incident::where('domain_id', $domain->id)
            ->whereBetween('created_at', [$weekStart, $weekEnd])
            ->orderBy('severity')
            ->orderBy('created_at')
            ->get();

        // Calculate statistics
        $stats = $this->calculateStats($snapshots, $deltas, $incidents);

        return [
            'snapshots' => $snapshots,
            'deltas' => $deltas,
            'incidents' => $incidents,
            'stats' => $stats,
        ];
    }

    /**
     * Calculate weekly statistics
     */
    protected function calculateStats($snapshots, $deltas, $incidents): array
    {
        $stats = [
            'scans_performed' => $snapshots->count(),
            'changes_detected' => $deltas->count(),
            'incidents_raised' => $incidents->count(),
            'critical_incidents' => $incidents->where('severity', 'critical')->count(),
            'average_score' => 0,
            'score_trend' => 'stable',
            'rbl_listings' => 0,
            'rbl_delistings' => 0,
        ];

        if ($snapshots->isNotEmpty()) {
            $stats['average_score'] = round($snapshots->avg('score'));
            
            // Calculate score trend
            $firstScore = $snapshots->first()->score;
            $lastScore = $snapshots->last()->score;
            $scoreDiff = $lastScore - $firstScore;
            
            if ($scoreDiff > 5) {
                $stats['score_trend'] = 'improving';
            } elseif ($scoreDiff < -5) {
                $stats['score_trend'] = 'declining';
            }
        }

        // Count RBL changes
        foreach ($deltas as $delta) {
            $rblChanges = $delta->getRblChanges();
            $stats['rbl_listings'] += count($rblChanges['listed']);
            $stats['rbl_delistings'] += count($rblChanges['delisted']);
        }

        return $stats;
    }

    /**
     * Check if we should skip sending the report (no activity)
     */
    protected function shouldSkipReport(array $reportData): bool
    {
        return $reportData['stats']['scans_performed'] === 0 &&
               $reportData['stats']['incidents_raised'] === 0;
    }

    /**
     * Generate PDF report
     */
    protected function generatePdf(Domain $domain, array $reportData, $weekStart, $weekEnd)
    {
        return Pdf::loadView('reports.weekly', [
            'domain' => $domain,
            'reportData' => $reportData,
            'weekStart' => $weekStart,
            'weekEnd' => $weekEnd,
        ])->setPaper('a4', 'portrait');
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('SendWeeklyReport job failed', [
            'error' => $exception->getMessage(),
        ]);
    }
}
