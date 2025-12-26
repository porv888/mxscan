<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\DmarcAlertSetting;
use App\Models\DmarcEvent;
use App\Models\DmarcSender;
use App\Services\Dmarc\DmarcAnalyticsService;
use App\Services\Dmarc\DmarcReportProcessor;
use App\Services\Dmarc\DmarcStatusService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class DmarcController extends Controller
{
    protected DmarcAnalyticsService $analytics;
    protected DmarcReportProcessor $processor;
    protected DmarcStatusService $statusService;

    public function __construct(
        DmarcAnalyticsService $analytics, 
        DmarcReportProcessor $processor,
        DmarcStatusService $statusService
    ) {
        $this->analytics = $analytics;
        $this->processor = $processor;
        $this->statusService = $statusService;
    }

    /**
     * Global DMARC overview page.
     */
    public function index(Request $request)
    {
        $user = $request->user();
        $overview = $this->analytics->getGlobalOverview($user->id);
        
        // Get all user domains with their DMARC status
        $allDomains = $user->domains()->get();
        $totalDomains = $allDomains->count();
        
        // Categorize domains by unified DMARC status
        $domainsByStatus = [
            DmarcStatusService::STATUS_NOT_ENABLED => collect(),
            DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN => collect(),
            DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING => collect(),
            DmarcStatusService::STATUS_ACTIVE => collect(),
            DmarcStatusService::STATUS_STALE => collect(),
        ];
        
        // Get status for each domain and categorize
        foreach ($allDomains as $domain) {
            $status = $this->statusService->getStatus($domain);
            $domain->dmarc_setup_status = $status; // Attach for view use
            
            // For domains with existing DMARC, get the smart update suggestion
            if ($status['status'] === DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN) {
                $domain->dmarc_update = $this->statusService->getUpdatedDmarcRecord($domain);
            }
            
            $domainsByStatus[$status['status']]->push($domain);
        }
        
        // Legacy compatibility: map to old variable names
        $domainsNeedingSetup = $domainsByStatus[DmarcStatusService::STATUS_NOT_ENABLED]
            ->merge($domainsByStatus[DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN]);
        
        $domainsWaitingForReports = $domainsByStatus[DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING];
        
        $domainsActive = $domainsByStatus[DmarcStatusService::STATUS_ACTIVE];
        
        $domainsStale = $domainsByStatus[DmarcStatusService::STATUS_STALE];

        return view('dmarc.index', compact(
            'overview', 
            'totalDomains', 
            'allDomains', 
            'domainsByStatus',
            'domainsNeedingSetup',
            'domainsWaitingForReports',
            'domainsActive',
            'domainsStale'
        ));
    }

    /**
     * Domain-specific DMARC visibility page.
     */
    public function show(Domain $domain, Request $request)
    {
        $this->authorize('view', $domain);

        $user = $request->user();
        $isPaid = $user->canUseMonitoring();

        // Determine time range based on plan
        $days = $request->get('days', $isPaid ? 30 : 7);
        $maxDays = $isPaid ? 90 : 7;
        $days = min((int) $days, $maxDays);

        // Get summary and comparison
        $summary = $this->analytics->getDomainSummary($domain, 7);
        $comparison = $this->analytics->getPeriodComparison($domain, 7);

        // Get trends for chart
        $trends = $this->analytics->getDailyTrends($domain, $days);

        // Get sender inventory with filters
        $senderStatus = $request->get('status');
        $newOnly = $request->boolean('new_only');
        $search = $request->get('search');
        $senderLimit = $isPaid ? 50 : 5;

        $senders = $this->analytics->getSenderInventory(
            $domain,
            $days,
            $senderStatus,
            $newOnly,
            $search,
            $senderLimit
        );

        // Get recent events
        $events = $this->analytics->getRecentEvents($domain, 7);

        // Get reporting orgs
        $reportingOrgs = $this->analytics->getReportingOrgs($domain, $days);

        // Get alert settings
        $alertSettings = DmarcAlertSetting::where('domain_id', $domain->id)
            ->where('user_id', $user->id)
            ->first();

        // Get unified DMARC setup status
        $dmarcStatus = $this->statusService->getStatus($domain);
        
        // Get updated DMARC record suggestion for domains with existing DMARC
        $dmarcUpdate = null;
        if ($dmarcStatus['status'] === 'enabled_not_mxscan') {
            $dmarcUpdate = $this->statusService->getUpdatedDmarcRecord($domain);
        }

        return view('dmarc.show', compact(
            'domain',
            'summary',
            'comparison',
            'trends',
            'senders',
            'events',
            'reportingOrgs',
            'alertSettings',
            'isPaid',
            'days',
            'maxDays',
            'dmarcStatus',
            'dmarcUpdate'
        ));
    }

    /**
     * Get sender details (AJAX).
     */
    public function getSender(Domain $domain, DmarcSender $sender)
    {
        $this->authorize('view', $domain);

        if ($sender->domain_id !== $domain->id) {
            abort(404);
        }

        return response()->json([
            'sender' => [
                'id' => $sender->id,
                'source_ip' => $sender->source_ip,
                'header_from' => $sender->header_from,
                'org_name' => $sender->org_name,
                'ptr_record' => $sender->ptr_record,
                'asn' => $sender->asn,
                'asn_org' => $sender->asn_org,
                'total_count' => $sender->total_count,
                'alignment_rate' => $sender->alignment_rate,
                'dkim_pass_rate' => $sender->dkim_pass_rate,
                'spf_pass_rate' => $sender->spf_pass_rate,
                'disposition_breakdown' => [
                    'none' => $sender->disposition_none,
                    'quarantine' => $sender->disposition_quarantine,
                    'reject' => $sender->disposition_reject,
                ],
                'dkim_domain' => $sender->dkim_domain,
                'dkim_selector' => $sender->dkim_selector,
                'spf_domain' => $sender->spf_domain,
                'first_seen_at' => $sender->first_seen_at?->format('M j, Y'),
                'last_seen_at' => $sender->last_seen_at?->format('M j, Y'),
                'is_new' => $sender->is_new,
                'is_risky' => $sender->is_risky,
                'suggested_fix' => $sender->suggested_fix,
            ],
        ]);
    }

    /**
     * Upload DMARC report manually.
     */
    public function upload(Domain $domain, Request $request)
    {
        $this->authorize('update', $domain);

        $request->validate([
            'report_file' => 'required|file|max:10240|mimes:xml,zip,gz',
        ]);

        $file = $request->file('report_file');
        $path = $file->store('dmarc/uploads');
        $fullPath = storage_path('app/' . $path);

        try {
            $report = $this->processor->processUploadedFile($fullPath, $domain);

            if ($report) {
                return back()->with('success', 'DMARC report uploaded and processed successfully.');
            }

            return back()->with('error', 'Failed to process the DMARC report. Please check the file format.');
        } finally {
            // Clean up uploaded file
            Storage::delete($path);
        }
    }

    /**
     * Update alert settings for a domain.
     */
    public function updateAlertSettings(Domain $domain, Request $request)
    {
        $this->authorize('update', $domain);

        $user = $request->user();

        if (!$user->canUseMonitoring()) {
            return back()->with('error', 'DMARC alerts require a paid plan.');
        }

        $validated = $request->validate([
            'new_sender_enabled' => 'boolean',
            'fail_spike_enabled' => 'boolean',
            'alignment_drop_enabled' => 'boolean',
            'dkim_fail_spike_enabled' => 'boolean',
            'spf_fail_spike_enabled' => 'boolean',
            'spike_threshold_pct' => 'integer|min:5|max:50',
            'min_volume_threshold' => 'integer|min:10|max:10000',
        ]);

        $settings = DmarcAlertSetting::getOrCreate($domain->id, $user->id);
        $settings->update($validated);

        return back()->with('success', 'Alert settings updated successfully.');
    }

    /**
     * Acknowledge an event.
     */
    public function acknowledgeEvent(Domain $domain, DmarcEvent $event, Request $request)
    {
        $this->authorize('update', $domain);

        if ($event->domain_id !== $domain->id) {
            abort(404);
        }

        $event->acknowledge($request->user()->id);

        return back()->with('success', 'Event acknowledged.');
    }

    /**
     * Get chart data (AJAX).
     */
    public function chartData(Domain $domain, Request $request)
    {
        $this->authorize('view', $domain);

        $user = $request->user();
        $isPaid = $user->canUseMonitoring();
        $maxDays = $isPaid ? 90 : 7;
        $days = min((int) $request->get('days', 30), $maxDays);

        $trends = $this->analytics->getDailyTrends($domain, $days);

        return response()->json([
            'labels' => $trends->pluck('date_label'),
            'datasets' => [
                'alignment' => $trends->pluck('alignment_rate'),
                'dkim' => $trends->pluck('dkim_pass_rate'),
                'spf' => $trends->pluck('spf_pass_rate'),
                'volume' => $trends->pluck('total_count'),
            ],
        ]);
    }

    /**
     * Check DNS for DMARC RUA configuration.
     * This performs a fresh DNS lookup and updates the verification state.
     */
    public function checkDns(Domain $domain, Request $request)
    {
        $this->authorize('view', $domain);

        // Use the unified status service for DNS check
        $dnsResult = $this->statusService->checkDnsAndSync($domain);
        
        // Get the updated unified status
        $domain->refresh();
        $status = $this->statusService->getStatus($domain);

        if ($request->expectsJson()) {
            return response()->json([
                'success' => $dnsResult['success'],
                'is_configured' => $dnsResult['has_mxscan_rua'],
                'status' => $status['status'],
                'status_label' => $status['label'],
                'badge_color' => $status['badge_color'],
                'helper_text' => $status['helper_text'],
                'message' => $dnsResult['message'],
                'dmarc_record' => $dnsResult['dmarc_record'],
                'checklist' => $status['checklist'],
            ]);
        }

        return back()->with($dnsResult['has_mxscan_rua'] ? 'success' : 'info', $dnsResult['message']);
    }

    /**
     * Get senders data (AJAX for filtering).
     */
    public function sendersData(Domain $domain, Request $request)
    {
        $this->authorize('view', $domain);

        $user = $request->user();
        $isPaid = $user->canUseMonitoring();
        $maxDays = $isPaid ? 90 : 7;
        $days = min((int) $request->get('days', 30), $maxDays);
        $limit = $isPaid ? 50 : 5;

        $senders = $this->analytics->getSenderInventory(
            $domain,
            $days,
            $request->get('status'),
            $request->boolean('new_only'),
            $request->get('search'),
            $limit
        );

        return response()->json([
            'senders' => $senders,
            'limited' => !$isPaid && $senders->count() >= $limit,
        ]);
    }
}
