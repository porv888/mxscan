<?php

namespace App\Http\Controllers;

use App\Models\DeliveryMonitor;
use App\Models\Domain;
use App\Support\SubaddressToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class DeliveryMonitorController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('verified');
    }

    /**
     * Display a listing of the user's delivery monitors
     */
    public function index(Request $request)
    {
        $user = $request->user();
        
        $monitors = DeliveryMonitor::where('user_id', $user->id)
            ->with('domain')
            ->latest()
            ->get();

        // Add incidents count for each monitor
        foreach ($monitors as $monitor) {
            if ($monitor->domain) {
                $monitor->incidents_last_7 = \App\Models\Incident::where('domain_id', $monitor->domain->id)
                    ->where('occurred_at', '>=', now()->subDays(7))
                    ->whereNull('resolved_at')
                    ->count();
            } else {
                $monitor->incidents_last_7 = 0;
            }
        }

        $monitors = new \Illuminate\Pagination\LengthAwarePaginator(
            $monitors->forPage($request->get('page', 1), 20),
            $monitors->count(),
            20,
            $request->get('page', 1),
            ['path' => $request->url(), 'query' => $request->query()]
        );

        $limit = $user->monitorLimit();
        $used = $user->monitorsUsed();

        return view('delivery-monitoring.index', compact('monitors', 'limit', 'used'));
    }

    /**
     * Show the form for creating a new monitor
     */
    public function create(Request $request)
    {
        $user = $request->user();
        
        // Check if user has reached their limit
        $limit = $user->monitorLimit();
        $used = $user->monitorsUsed();
        
        if ($used >= $limit) {
            return redirect()->route('delivery-monitoring.index')
                ->with('error', 'Monitor limit reached for your plan. Please upgrade to create more monitors.');
        }

        $domains = Domain::where('user_id', $user->id)
            ->orderBy('domain')
            ->get();

        return view('delivery-monitoring.create', compact('domains', 'limit', 'used'));
    }

    /**
     * Store a newly created monitor
     */
    public function store(Request $request)
    {
        $user = $request->user();

        // Enforce plan limits
        $limit = $user->monitorLimit();
        $count = DeliveryMonitor::where('user_id', $user->id)->count();
        
        if ($count >= $limit) {
            return back()->with('error', 'Monitor limit reached for your plan. Please upgrade to create more monitors.');
        }

        $data = $request->validate([
            'label'     => 'required|string|max:120',
            'domain_id' => 'nullable|exists:domains,id',
        ]);

        // Verify domain ownership if provided
        if (isset($data['domain_id'])) {
            $domain = Domain::find($data['domain_id']);
            if (!$domain || $domain->user_id !== $user->id) {
                return back()->with('error', 'Invalid domain selected.');
            }
        }

        // Create monitor with temporary values
        $monitor = new DeliveryMonitor($data + ['user_id' => $user->id]);
        $monitor->token = 'tmp';
        $monitor->inbox_address = 'temp';
        $monitor->save();

        // Now generate final token and address with actual ID
        $token = SubaddressToken::make($monitor->id, config('app.key'));
        $monitor->token = $token;
        $monitor->inbox_address = "monitor+{$token}@mxscan.me";
        $monitor->save();

        return redirect()->route('delivery-monitoring.show', $monitor)
            ->with('status', 'Monitor created successfully.');
    }

    /**
     * Display the specified monitor
     */
    public function show(Request $request, DeliveryMonitor $monitor)
    {
        $this->authorize('view', $monitor);

        $monitor->load('domain');
        
        // Get filters from request
        $range = $request->get('range', '24h');
        $verdict = $request->get('verdict', 'all');
        
        // Determine date range
        $rangeStart = match($range) {
            '7d' => now()->subDays(7),
            '30d' => now()->subDays(30),
            default => now()->subHours(24),
        };
        
        // Build query with filters
        $checksQuery = $monitor->checks()
            ->where('received_at', '>=', $rangeStart)
            ->latest('received_at');
            
        if ($verdict !== 'all') {
            $checksQuery->where('verdict', $verdict);
        }
        
        $checks = $checksQuery->paginate(25)->appends([
            'range' => $range,
            'verdict' => $verdict,
        ]);

        $incidentsLast7 = $monitor->incidentsLast7Days();
        
        // Compute stats
        $stats = $this->computeStats($monitor);

        return view('delivery-monitoring.show', compact('monitor', 'checks', 'incidentsLast7', 'stats', 'range', 'verdict'));
    }
    
    /**
     * Compute statistics for the monitor
     */
    private function computeStats(DeliveryMonitor $monitor): array
    {
        $now = now();
        
        // Get checks for last 24h
        $checks24h = $monitor->checks()
            ->where('received_at', '>=', $now->copy()->subHours(24))
            ->get();
            
        // Get checks for previous 24h (for comparison)
        $checksPrev24h = $monitor->checks()
            ->where('received_at', '>=', $now->copy()->subHours(48))
            ->where('received_at', '<', $now->copy()->subHours(24))
            ->get();
        
        // Calculate TTI statistics (Median and P95)
        $ttiValues24h = $checks24h->whereNotNull('tti_ms')->pluck('tti_ms')->sort()->values();
        $ttiCount = $ttiValues24h->count();
        
        $medianTti = null;
        $p95Tti = null;
        
        if ($ttiCount > 0) {
            // Calculate median
            $middle = floor($ttiCount / 2);
            if ($ttiCount % 2 == 0) {
                $medianTti = (int) round(($ttiValues24h[$middle - 1] + $ttiValues24h[$middle]) / 2 / 1000);
            } else {
                $medianTti = (int) round($ttiValues24h[$middle] / 1000);
            }
            
            // Calculate P95 (95th percentile)
            $p95Index = (int) ceil($ttiCount * 0.95) - 1;
            $p95Tti = (int) round($ttiValues24h[$p95Index] / 1000);
        }
        
        // Keep average for backward compatibility
        $avgTti24h = $ttiValues24h->count() > 0 ? (int) round($ttiValues24h->avg() / 1000) : null;
        
        $avgTtiPrev24h = $checksPrev24h->whereNotNull('tti_ms')->avg('tti_ms');
        $avgTtiPrev24h = $avgTtiPrev24h ? (int) round($avgTtiPrev24h / 1000) : null;
        
        // Calculate auth pass rates - excluding "none" (null) values
        // SPF: pass / (pass + fail), excluding none
        $spfPass = $checks24h->where('spf_pass', true)->count();
        $spfFail = $checks24h->where('spf_pass', false)->count();
        $spfNone = $checks24h->whereNull('spf_pass')->count();
        $spfTotal = $spfPass + $spfFail;
        $spfPassRate = $spfTotal > 0 ? round(($spfPass / $spfTotal) * 100, 1) : null;
        
        // DKIM: pass / (pass + fail), excluding none
        $dkimPass = $checks24h->where('dkim_pass', true)->count();
        $dkimFail = $checks24h->where('dkim_pass', false)->count();
        $dkimNone = $checks24h->whereNull('dkim_pass')->count();
        $dkimTotal = $dkimPass + $dkimFail;
        $dkimPassRate = $dkimTotal > 0 ? round(($dkimPass / $dkimTotal) * 100, 1) : null;
        
        // DMARC: pass / (pass + fail), excluding none
        $dmarcPass = $checks24h->where('dmarc_pass', true)->count();
        $dmarcFail = $checks24h->where('dmarc_pass', false)->count();
        $dmarcNone = $checks24h->whereNull('dmarc_pass')->count();
        $dmarcTotal = $dmarcPass + $dmarcFail;
        $dmarcPassRate = $dmarcTotal > 0 ? round(($dmarcPass / $dmarcTotal) * 100, 1) : null;
        
        return [
            'avg_tti_24h' => $avgTti24h,
            'median_tti_24h' => $medianTti,
            'p95_tti_24h' => $p95Tti,
            'tti_sample_size' => $ttiCount,
            'avg_tti_prev_24h' => $avgTtiPrev24h,
            'spf_pass_rate' => $spfPassRate,
            'spf_sample_size' => $spfTotal,
            'spf_none_count' => $spfNone,
            'dkim_pass_rate' => $dkimPassRate,
            'dkim_sample_size' => $dkimTotal,
            'dkim_none_count' => $dkimNone,
            'dmarc_pass_rate' => $dmarcPassRate,
            'dmarc_sample_size' => $dmarcTotal,
            'dmarc_none_count' => $dmarcNone,
        ];
    }

    /**
     * Pause a monitor
     */
    public function pause(DeliveryMonitor $monitor)
    {
        $this->authorize('update', $monitor);

        $monitor->update(['status' => 'paused']);

        return back()->with('status', 'Monitor paused successfully.');
    }

    /**
     * Resume a monitor
     */
    public function resume(DeliveryMonitor $monitor)
    {
        $this->authorize('update', $monitor);

        $monitor->update(['status' => 'active']);

        return back()->with('status', 'Monitor resumed successfully.');
    }

    /**
     * Remove the specified monitor
     */
    public function destroy(DeliveryMonitor $monitor)
    {
        $this->authorize('delete', $monitor);

        $monitor->delete();

        return redirect()->route('delivery-monitoring.index')
            ->with('status', 'Monitor deleted successfully.');
    }
    
    /**
     * Get check details for API (used by details modal)
     */
    public function getCheckDetails($checkId)
    {
        $check = \App\Models\DeliveryCheck::findOrFail($checkId);
        
        // Verify user owns this check's monitor
        if ($check->monitor->user_id !== auth()->id()) {
            abort(403, 'Unauthorized access to check details.');
        }
        
        // Generate "why" summary based on failures
        $whySummary = $this->generateWhySummary($check);
        
        // Check if verification was done by app (server-agnostic)
        $verifiedByApp = !empty($check->auth_meta);
        
        // Enhanced auth_meta with proper structure for modal
        $authMeta = $check->auth_meta ?? [];
        if (!empty($authMeta)) {
            // Ensure IP is available from multiple sources
            if (empty($authMeta['ip'])) {
                $authMeta['ip'] = $authMeta['analysis']['mx_ip'] ?? 
                                  $authMeta['spf']['ip'] ?? 
                                  $check->mx_ip ?? null;
            }
            
            // Ensure envelope from is available
            if (empty($authMeta['mailfrom'])) {
                $authMeta['mailfrom'] = $authMeta['spf']['domain'] ?? null;
                if ($authMeta['mailfrom']) {
                    $authMeta['mailfrom'] = 'postmaster@' . $authMeta['mailfrom'];
                }
            }
            
            // Ensure header from is available
            if (empty($authMeta['header_from'])) {
                $authMeta['header_from'] = $check->from_addr ?? null;
            }
            
            // Ensure DMARC policy is available
            if (!empty($authMeta['dmarc']) && empty($authMeta['dmarc']['policy'])) {
                // Try to fetch from cached DNS if not present
                $headerFromDomain = $authMeta['dmarc']['domain'] ?? 
                                   $authMeta['header_from_domain'] ?? null;
                if ($headerFromDomain) {
                    try {
                        $dmarcRecord = $this->fetchDmarcPolicy($headerFromDomain);
                        if ($dmarcRecord) {
                            $authMeta['dmarc']['policy'] = $dmarcRecord;
                        }
                    } catch (\Exception $e) {
                        // Silently fail
                    }
                }
            }
        }
        
        return response()->json([
            'id' => $check->id,
            'received_at' => $check->received_at->format('M d, Y H:i:s'),
            'from_addr' => $check->from_addr,
            'subject' => $check->subject,
            'tti' => $check->getFormattedTti(),
            'spf_badge' => view('components.delivery.auth-chip', ['value' => $check->spf_pass, 'label' => 'SPF'])->render(),
            'dkim_badge' => view('components.delivery.auth-chip', ['value' => $check->dkim_pass, 'label' => 'DKIM'])->render(),
            'dmarc_badge' => view('components.delivery.auth-chip', ['value' => $check->dmarc_pass, 'label' => 'DMARC'])->render(),
            'raw_headers' => is_array($check->raw_headers) ? json_encode($check->raw_headers, JSON_PRETTY_PRINT) : $check->raw_headers,
            'why_summary' => $whySummary,
            'verified_by_app' => $verifiedByApp,
            'auth_meta' => $authMeta,
            'ar_raw' => $check->ar_raw,
        ]);
    }
    
    /**
     * Fetch DMARC policy from DNS with caching
     */
    private function fetchDmarcPolicy(string $domain): ?string
    {
        try {
            $dns = new \Spatie\Dns\Dns();
            $records = $dns->getRecords('_dmarc.' . $domain, 'TXT');
            
            foreach ($records as $record) {
                // Spatie\Dns returns objects, not arrays
                $txt = is_object($record) ? $record->txt() : ($record['txt'] ?? null);
                
                if ($txt && str_starts_with($txt, 'v=DMARC1')) {
                    // Extract policy
                    if (preg_match('/p=([a-z]+)/i', $txt, $matches)) {
                        return $matches[1];
                    }
                }
            }
        } catch (\Exception $e) {
            // Silently fail
            \Illuminate\Support\Facades\Log::debug('fetchDmarcPolicy failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
        }
        
        return null;
    }
    
    /**
     * Generate a human-readable summary of why checks failed
     */
    private function generateWhySummary($check): ?string
    {
        $issues = [];
        
        // Use auth_meta notes if available (more detailed)
        if (!empty($check->auth_meta['notes'])) {
            $notes = $check->auth_meta['notes'];
            foreach ($notes as $note) {
                // Filter out informational notes, keep only issues
                if (stripos($note, 'failed') !== false || 
                    stripos($note, 'not found') !== false ||
                    stripos($note, 'unable') !== false ||
                    stripos($note, 'no public') !== false) {
                    $issues[] = $note;
                }
            }
        }
        
        // Fallback to generic messages if no detailed notes
        if (empty($issues)) {
            if ($check->spf_pass === false) {
                $issues[] = "SPF failed: The sending server's IP is not authorized in your domain's SPF record.";
            }
            
            if ($check->dkim_pass === false) {
                $issues[] = "DKIM failed: The email signature is invalid or missing. Check your mail server's DKIM configuration.";
            }
            
            if ($check->dmarc_pass === false) {
                $issues[] = "DMARC failed: Domain alignment check failed. Ensure your From domain matches your SPF/DKIM domains.";
            }
        }
        
        if ($check->tti_ms && $check->getTtiSeconds() > 1800) {
            $issues[] = "Slow delivery detected: Time-to-inbox exceeded 30 minutes. Check for mail server delays or routing issues.";
        }
        
        if (empty($issues)) {
            return $check->verdict === 'ok' 
                ? "All authentication checks passed successfully. Your email delivery is working correctly."
                : null;
        }
        
        return implode(' ', $issues);
    }
}
