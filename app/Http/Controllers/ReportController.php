<?php

namespace App\Http\Controllers;

use App\Models\Scan;
use App\Models\Domain;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ReportController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
    }

    /**
     * Display a listing of scan reports with filters.
     */
    public function index(Request $request)
    {
        $query = Scan::with('domain')
            ->where('user_id', Auth::id());

        // Filter by domain
        if ($request->filled('domain_id')) {
            $query->where('domain_id', $request->domain_id);
        }

        // Filter by scan type
        if ($request->filled('scan_type')) {
            $query->where('type', $request->scan_type);
        }

        // Filter by result status
        if ($request->filled('result')) {
            if ($request->result === 'ok') {
                $query->where('score', '>=', 80);
            } elseif ($request->result === 'warn') {
                $query->whereBetween('score', [60, 79]);
            } elseif ($request->result === 'error') {
                $query->where('score', '<', 60);
            }
        }

        // Filter by date range
        if ($request->filled('date_from')) {
            $query->whereDate('created_at', '>=', $request->date_from);
        }
        if ($request->filled('date_to')) {
            $query->whereDate('created_at', '<=', $request->date_to);
        }

        $scans = $query->orderBy('created_at', 'desc')->paginate(20);

        // Get domains for filter dropdown
        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('reports.index', compact('scans', 'domains'));
    }

    /**
     * Display the specified scan report (reuse existing scan show view).
     */
    public function show(Scan $scan)
    {
        // Only allow owner
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to report.');
        }

        // Load relationships and refresh domain to get latest expiry dates
        $scan->load(['domain', 'blacklistResults']);
        $domain = $scan->domain->fresh();

        // Determine enabled services based on scan type
        $enabled = [
            'dns' => $scan->hasDnsResults(),
            'spf' => $scan->hasSpfResults(),
            'blacklist' => $scan->hasBlacklistResults(),
            'delivery' => false, // Delivery monitoring is separate
        ];

        // Get scan type flags
        $isBlacklistOnly = $scan->isBlacklistOnly();
        $hasDns = $scan->hasDnsResults();
        $hasSpf = $scan->hasSpfResults();
        $hasBlacklist = $scan->hasBlacklistResults();

        // Get latest and previous snapshots for delta calculation
        $snapshot = $domain->latestScanSnapshot;
        $lastSnapshot = $domain->scanSnapshots()
            ->where('id', '!=', $snapshot?->id)
            ->latest('created_at')
            ->first();

        // Calculate score delta
        $scoreDelta = null;
        if ($snapshot && $lastSnapshot) {
            $scoreDelta = ($snapshot->score ?? 0) - ($lastSnapshot->score ?? 0);
        }

        // Parse result data
        $resultData = $scan->result_json ?? [];
        $records = $resultData['dns']['records'] ?? $resultData ?? [];

        // Extract metrics for KPIs
        $spfInfo = $resultData['spf'] ?? null;
        $spfLookupCount = $spfInfo['lookups'] ?? $domain->spf_lookup_count ?? null;
        $spfMax = 10;
        $spfSuggestion = $spfInfo['flattened'] ?? null;

        // DMARC metrics
        $dmarcData = $records['DMARC'] ?? null;
        $dmarcPolicy = null;
        $dmarcAligned = null;
        if ($dmarcData && $dmarcData['status'] === 'found') {
            $dmarcRecord = $dmarcData['data'];
            if (preg_match('/p=([^;]+)/', $dmarcRecord, $matches)) {
                $dmarcPolicy = $matches[1];
            }
            $dmarcAligned = (str_contains($dmarcRecord, 'aspf=') || str_contains($dmarcRecord, 'adkim='));
        }

        // TLS/MTA-STS status
        $tlsrptOk = isset($records['TLS-RPT']) && $records['TLS-RPT']['status'] === 'found';
        $mtastsOk = isset($records['MTA-STS']) && $records['MTA-STS']['status'] === 'found';

        // Blacklist metrics
        $blacklistData = $resultData['blacklist'] ?? [];
        $blacklistHits = $blacklistData['listed_count'] ?? 0;
        $blacklistTotal = $blacklistData['total_checks'] ?? 0;
        $blacklistRows = $scan->blacklistResults;

        // Domain/SSL expiry
        $domainDays = $domain->getDaysUntilDomainExpiry();
        $sslDays = $domain->getDaysUntilSslExpiry();

        // Get recent incidents (last 7 days, unresolved)
        $incidents = $domain->incidents()
            ->where('created_at', '>=', now()->subDays(7))
            ->whereNull('resolved_at')
            ->orderByDesc('severity')
            ->orderByDesc('created_at')
            ->get();

        // Get recent delivery monitors (if enabled)
        $deliveries = collect();
        if ($enabled['delivery']) {
            $deliveries = $domain->deliveryMonitors()
                ->latest('created_at')
                ->limit(5)
                ->get();
        }

        // Get current schedule cadence
        $activeSchedule = $domain->activeSchedule;
        $cadence = 'off';
        if ($activeSchedule) {
            $frequency = $activeSchedule->frequency;
            $cadence = $frequency === 'daily' ? 'daily' : ($frequency === 'weekly' ? 'weekly' : 'off');
        }

        return view('scans.show', compact(
            'scan',
            'domain',
            'enabled',
            'isBlacklistOnly',
            'hasDns',
            'hasSpf',
            'hasBlacklist',
            'snapshot',
            'lastSnapshot',
            'scoreDelta',
            'resultData',
            'records',
            'spfLookupCount',
            'spfMax',
            'spfSuggestion',
            'dmarcPolicy',
            'dmarcAligned',
            'tlsrptOk',
            'mtastsOk',
            'blacklistHits',
            'blacklistTotal',
            'blacklistRows',
            'domainDays',
            'sslDays',
            'incidents',
            'deliveries',
            'cadence'
        ));
    }

    /**
     * Export scan reports as CSV.
     */
    public function export(Request $request)
    {
        $query = Scan::with('domain')
            ->where('user_id', Auth::id());

        // Apply same filters as index
        if ($request->filled('domain_id')) {
            $query->where('domain_id', $request->domain_id);
        }
        if ($request->filled('scan_type')) {
            $query->where('type', $request->scan_type);
        }
        if ($request->filled('result')) {
            if ($request->result === 'ok') {
                $query->where('score', '>=', 80);
            } elseif ($request->result === 'warn') {
                $query->whereBetween('score', [60, 79]);
            } elseif ($request->result === 'error') {
                $query->where('score', '<', 60);
            }
        }
        if ($request->filled('date_from')) {
            $query->whereDate('created_at', '>=', $request->date_from);
        }
        if ($request->filled('date_to')) {
            $query->whereDate('created_at', '<=', $request->date_to);
        }

        $scans = $query->orderBy('created_at', 'desc')->get();

        $filename = 'scan-reports-' . now()->format('Y-m-d') . '.csv';
        
        $headers = [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
        ];

        $callback = function() use ($scans) {
            $file = fopen('php://output', 'w');
            
            // CSV header
            fputcsv($file, ['Date/Time', 'Domain', 'Scan Type', 'Score', 'Status', 'Duration (ms)']);
            
            foreach ($scans as $scan) {
                fputcsv($file, [
                    $scan->created_at->format('Y-m-d H:i:s'),
                    $scan->domain->domain,
                    $scan->getTypeLabel(),
                    $scan->score ?? 'N/A',
                    $scan->status,
                    $scan->duration_ms ?? 'N/A',
                ]);
            }
            
            fclose($file);
        };

        return response()->stream($callback, 200, $headers);
    }
}
