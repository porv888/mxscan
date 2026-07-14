<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Concerns\PreparesScanReport;
use App\Models\Scan;
use App\Models\Domain;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ReportController extends Controller
{
    use PreparesScanReport;

    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
        $this->middleware('entitlement:report_export')->only('export');
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
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to report.');
        }

        return view('scans.show', $this->prepareScanReportViewData($scan));
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
