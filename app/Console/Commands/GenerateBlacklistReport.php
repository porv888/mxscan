<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Domain;
use App\Models\BlacklistResult;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Storage;

class GenerateBlacklistReport extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'blacklist:report 
                            {--user= : Generate report for specific user ID}
                            {--domain= : Generate report for specific domain}
                            {--days=30 : Number of days to include in report}
                            {--format=table : Output format (table, json, csv)}
                            {--save : Save report to storage}';

    /**
     * The console command description.
     */
    protected $description = 'Generate comprehensive blacklist monitoring reports';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $userId = $this->option('user');
        $domainName = $this->option('domain');
        $days = $this->option('days');
        $format = $this->option('format');
        $save = $this->option('save');

        $startDate = Carbon::now()->subDays($days);
        
        $this->info("Generating blacklist report for the last {$days} days...");

        // Build query
        $query = BlacklistResult::with(['scan.domain', 'scan.user'])
            ->where('created_at', '>=', $startDate);

        if ($userId) {
            $query->whereHas('scan.user', function($q) use ($userId) {
                $q->where('id', $userId);
            });
        }

        if ($domainName) {
            $query->whereHas('scan.domain', function($q) use ($domainName) {
                $q->where('domain', $domainName);
            });
        }

        $results = $query->orderBy('created_at', 'desc')->get();

        if ($results->isEmpty()) {
            $this->warn('No blacklist results found for the specified criteria.');
            return 0;
        }

        // Generate report data
        $reportData = $this->generateReportData($results, $startDate);

        // Output report
        switch ($format) {
            case 'json':
                $output = $this->generateJsonReport($reportData);
                break;
            case 'csv':
                $output = $this->generateCsvReport($reportData);
                break;
            default:
                $this->displayTableReport($reportData);
                $output = null;
                break;
        }

        // Save to file if requested
        if ($save && $output) {
            $filename = "blacklist-report-" . now()->format('Y-m-d-H-i-s') . ".{$format}";
            Storage::disk('local')->put("reports/{$filename}", $output);
            $this->info("Report saved to: storage/app/reports/{$filename}");
        }

        return 0;
    }

    /**
     * Generate report data structure.
     */
    private function generateReportData($results, $startDate)
    {
        $summary = [
            'period' => [
                'start' => $startDate->format('Y-m-d'),
                'end' => now()->format('Y-m-d'),
                'days' => $startDate->diffInDays(now())
            ],
            'totals' => [
                'checks' => $results->count(),
                'listed' => $results->where('status', 'listed')->count(),
                'clean' => $results->where('status', 'ok')->count(),
                'unique_domains' => $results->pluck('scan.domain.domain')->unique()->count(),
                'unique_ips' => $results->pluck('ip_address')->unique()->count()
            ]
        ];

        // Domain breakdown
        $domainStats = $results->groupBy('scan.domain.domain')->map(function($domainResults, $domain) {
            $listed = $domainResults->where('status', 'listed');
            return [
                'domain' => $domain,
                'total_checks' => $domainResults->count(),
                'listed_count' => $listed->count(),
                'clean_count' => $domainResults->count() - $listed->count(),
                'unique_ips' => $domainResults->pluck('ip_address')->unique()->count(),
                'first_check' => $domainResults->min('created_at'),
                'last_check' => $domainResults->max('created_at'),
                'status' => $listed->count() > 0 ? 'listed' : 'clean'
            ];
        })->values();

        // RBL provider stats
        $providerStats = $results->groupBy('provider')->map(function($providerResults, $provider) {
            $listed = $providerResults->where('status', 'listed');
            return [
                'provider' => $provider,
                'total_checks' => $providerResults->count(),
                'listed_count' => $listed->count(),
                'listing_rate' => $providerResults->count() > 0 ? 
                    round(($listed->count() / $providerResults->count()) * 100, 2) : 0
            ];
        })->sortByDesc('total_checks')->values();

        // Recent listings
        $recentListings = $results->where('status', 'listed')
            ->sortByDesc('created_at')
            ->take(20)
            ->map(function($result) {
                return [
                    'date' => $result->created_at->format('Y-m-d H:i:s'),
                    'domain' => $result->scan->domain->domain,
                    'ip_address' => $result->ip_address,
                    'provider' => $result->provider,
                    'message' => $result->message
                ];
            })->values();

        return [
            'summary' => $summary,
            'domains' => $domainStats,
            'providers' => $providerStats,
            'recent_listings' => $recentListings
        ];
    }

    /**
     * Display table format report.
     */
    private function displayTableReport($data)
    {
        $this->info('=== BLACKLIST MONITORING REPORT ===');
        $this->newLine();

        // Summary
        $this->info('Summary:');
        $this->table(
            ['Metric', 'Value'],
            [
                ['Report Period', $data['summary']['period']['start'] . ' to ' . $data['summary']['period']['end']],
                ['Total Checks', number_format($data['summary']['totals']['checks'])],
                ['Listed Results', number_format($data['summary']['totals']['listed'])],
                ['Clean Results', number_format($data['summary']['totals']['clean'])],
                ['Domains Monitored', number_format($data['summary']['totals']['unique_domains'])],
                ['Unique IPs Checked', number_format($data['summary']['totals']['unique_ips'])],
            ]
        );

        // Domain stats
        if (!empty($data['domains'])) {
            $this->newLine();
            $this->info('Domain Statistics:');
            $this->table(
                ['Domain', 'Total Checks', 'Listed', 'Status'],
                $data['domains']->map(function($domain) {
                    return [
                        $domain['domain'],
                        $domain['total_checks'],
                        $domain['listed_count'],
                        $domain['status'] === 'listed' ? '🔴 Listed' : '🟢 Clean'
                    ];
                })->toArray()
            );
        }

        // Provider stats
        if (!empty($data['providers'])) {
            $this->newLine();
            $this->info('RBL Provider Statistics:');
            $this->table(
                ['Provider', 'Total Checks', 'Listings', 'Listing Rate'],
                $data['providers']->map(function($provider) {
                    return [
                        $provider['provider'],
                        $provider['total_checks'],
                        $provider['listed_count'],
                        $provider['listing_rate'] . '%'
                    ];
                })->toArray()
            );
        }

        // Recent listings
        if (!empty($data['recent_listings']) && $data['recent_listings']->count() > 0) {
            $this->newLine();
            $this->info('Recent Blacklist Detections:');
            $this->table(
                ['Date', 'Domain', 'IP Address', 'Provider'],
                $data['recent_listings']->map(function($listing) {
                    return [
                        $listing['date'],
                        $listing['domain'],
                        $listing['ip_address'],
                        $listing['provider']
                    ];
                })->toArray()
            );
        }
    }

    /**
     * Generate JSON format report.
     */
    private function generateJsonReport($data)
    {
        return json_encode($data, JSON_PRETTY_PRINT);
    }

    /**
     * Generate CSV format report.
     */
    private function generateCsvReport($data)
    {
        $csv = "Domain,IP Address,Provider,Status,Date,Message\n";
        
        // Add domain data
        foreach ($data['recent_listings'] as $listing) {
            $csv .= sprintf(
                "%s,%s,%s,%s,%s,%s\n",
                $listing['domain'],
                $listing['ip_address'],
                $listing['provider'],
                'listed',
                $listing['date'],
                str_replace(',', ';', $listing['message'] ?? '')
            );
        }

        return $csv;
    }
}