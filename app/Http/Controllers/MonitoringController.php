<?php

namespace App\Http\Controllers;

use App\Models\Incident;
use App\Models\ScanSnapshot;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class MonitoringController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('verified');
    }

    /**
     * Show user's incidents
     */
    public function incidents(Request $request)
    {
        // Check if user can access monitoring features
        if (!Auth::user()->canUseMonitoring()) {
            return redirect()->route('pricing')->with('error', 'Monitoring features are available with Premium and Ultra plans. Please upgrade to access incident tracking.');
        }

        $query = Incident::whereHas('domain', function ($q) {
            $q->where('user_id', Auth::id());
        })->with(['domain', 'deliveryCheck']);

        // Filter by severity if requested
        if ($request->filled('severity')) {
            $query->where('severity', $request->severity);
        }

        // Filter by domain if requested
        if ($request->filled('domain_id')) {
            $query->where('domain_id', $request->domain_id);
        }

        // Filter by date range - default to last 7 days if no filters
        if ($request->filled('from')) {
            $query->where('occurred_at', '>=', $request->from);
        } elseif (!$request->hasAny(['severity', 'domain_id', 'to'])) {
            // Default: last 7 days
            $query->where('occurred_at', '>=', now()->subDays(7));
        }
        
        if ($request->filled('to')) {
            $query->where('occurred_at', '<=', $request->to . ' 23:59:59');
        }

        $incidents = $query->orderBy('occurred_at', 'desc')->paginate(20);

        // Get user's domains for filter dropdown
        $domains = Auth::user()->domains()->orderBy('domain')->get();

        return view('monitoring.incidents', compact('incidents', 'domains'));
    }

    /**
     * Show specific incident
     */
    public function showIncident(Incident $incident)
    {
        // Check if user can access monitoring features
        if (!Auth::user()->canUseMonitoring()) {
            return redirect()->route('pricing')->with('error', 'Monitoring features are available with Premium and Ultra plans.');
        }

        // Check if user owns this incident's domain
        if ($incident->domain->user_id !== Auth::id()) {
            abort(403, 'You do not have permission to view this incident.');
        }

        $incident->load(['domain', 'snapshot']);

        return view('monitoring.incident', compact('incident'));
    }

    /**
     * Show user's snapshots
     */
    public function snapshots(Request $request)
    {
        // Check if user can access monitoring features
        if (!Auth::user()->canUseMonitoring()) {
            return redirect()->route('pricing')->with('error', 'Monitoring features are available with Premium and Ultra plans.');
        }

        $query = ScanSnapshot::whereHas('domain', function ($q) {
            $q->where('user_id', Auth::id());
        })->with(['domain']);

        // Filter by scan type if requested
        if ($request->filled('scan_type')) {
            $query->where('scan_type', $request->scan_type);
        }

        // Filter by domain if requested
        if ($request->filled('domain_id')) {
            $query->where('domain_id', $request->domain_id);
        }

        $snapshots = $query->orderBy('created_at', 'desc')->paginate(20);

        // Get user's domains for filter dropdown
        $domains = Auth::user()->domains()->orderBy('domain')->get();

        return view('monitoring.snapshots', compact('snapshots', 'domains'));
    }

    /**
     * Show specific snapshot
     */
    public function showSnapshot(ScanSnapshot $snapshot)
    {
        // Check if user can access monitoring features
        if (!Auth::user()->canUseMonitoring()) {
            return redirect()->route('pricing')->with('error', 'Monitoring features are available with Premium and Ultra plans.');
        }

        // Check if user owns this snapshot's domain
        if ($snapshot->domain->user_id !== Auth::id()) {
            abort(403, 'You do not have permission to view this snapshot.');
        }

        $snapshot->load(['domain']);

        return view('monitoring.snapshot', compact('snapshot'));
    }
}
