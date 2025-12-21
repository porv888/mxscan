<?php

namespace App\Services;

use App\Models\Domain;
use Barryvdh\DomPDF\Facade\Pdf;

class ReportService
{
    /**
     * Generate a PDF evidence pack for the domain's current scan status
     */
    public function currentScanPdf(Domain $domain): string
    {
        $latestScan = $domain->scans()->latest()->first();
        $latestSpfCheck = $domain->spfChecks()->latest()->first();
        $blacklistResults = [];
        
        // Get blacklist results if available
        if ($latestScan && $latestScan->blacklistResults) {
            $blacklistResults = $latestScan->blacklistResults;
        }

        // Get RBL provider metadata
        $rblProviders = config('rbl.providers', []);

        $data = [
            'domain' => $domain,
            'scan' => $latestScan,
            'spfCheck' => $latestSpfCheck,
            'blacklistResults' => $blacklistResults,
            'rblProviders' => $rblProviders,
            'generatedAt' => now(),
        ];

        $html = view('reports.evidence', $data)->render();

        return Pdf::loadHTML($html)
            ->setPaper('a4')
            ->setOptions([
                'defaultFont' => 'sans-serif',
                'isRemoteEnabled' => false,
                'isHtml5ParserEnabled' => true,
            ])
            ->output();
    }

    /**
     * Generate a comprehensive weekly report PDF
     */
    public function weeklyReportPdf(Domain $domain, array $incidents = [], array $scans = []): string
    {
        $data = [
            'domain' => $domain,
            'incidents' => $incidents,
            'scans' => $scans,
            'weekStart' => now()->subWeek()->startOfWeek(),
            'weekEnd' => now()->endOfWeek(),
            'generatedAt' => now(),
        ];

        $html = view('reports.weekly', $data)->render();

        return Pdf::loadHTML($html)
            ->setPaper('a4')
            ->setOptions([
                'defaultFont' => 'sans-serif',
                'isRemoteEnabled' => false,
                'isHtml5ParserEnabled' => true,
            ])
            ->output();
    }
}
