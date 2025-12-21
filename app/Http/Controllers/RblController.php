<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\Incident;
use App\Services\ReportService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Auth;

class RblController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Get delisting information for a specific RBL provider
     */
    public function info(Request $request, Domain $domain, string $provider)
    {
        // Ensure user owns the domain
        if ($domain->user_id !== Auth::id()) {
            abort(403);
        }

        $meta = config("rbl.providers.$provider");
        abort_unless($meta, 404, "RBL provider not found");

        return response()->json([
            'provider' => $provider,
            'name' => $meta['name'],
            'delist_url' => $meta['delist_url'],
            'site' => $meta['site'],
            'requires_evidence' => $meta['requires_evidence'],
            'instructions' => $meta['instructions'],
            'email' => $meta['contact_email'],
            'prefilled_email' => $this->buildEmail($domain, $meta),
        ]);
    }

    /**
     * Generate pre-filled email template for providers that accept email requests
     */
    protected function buildEmail(Domain $domain, array $meta): ?array
    {
        if (empty($meta['contact_email'])) {
            return null;
        }

        $user = Auth::user();
        $subject = "Delisting request for {$domain->domain}";
        $body = "Hello,\n\n"
              . "Please review and delist our domain {$domain->domain} and its associated IP addresses from {$meta['name']}.\n\n"
              . "Summary of remediation actions taken:\n"
              . "- SPF and DMARC records have been properly configured\n"
              . "- All open mail relays have been secured\n"
              . "- Mail server security has been hardened\n"
              . "- No unauthorized spam activity has occurred since remediation\n"
              . "- All compromised systems have been cleaned and secured\n\n"
              . "We have attached our latest security scan report as evidence of our current email security posture.\n\n"
              . "Please confirm the delisting and let us know if you need any additional information.\n\n"
              . "Thank you for your assistance,\n"
              . "{$user->name}\n"
              . "Email: {$user->email}";

        return [
            'to' => $meta['contact_email'],
            'subject' => $subject,
            'body' => $body,
        ];
    }

    /**
     * Generate and download evidence pack (PDF of latest scan)
     */
    public function evidence(Domain $domain, ReportService $reports)
    {
        // Ensure user owns the domain
        if ($domain->user_id !== Auth::id()) {
            abort(403);
        }

        try {
            $pdf = $reports->currentScanPdf($domain);
            
            return Response::make($pdf, 200, [
                'Content-Type' => 'application/pdf',
                'Content-Disposition' => 'attachment; filename="mxscan-' . $domain->domain . '-evidence.pdf"',
            ]);
        } catch (\Exception $e) {
            return back()->with('error', 'Unable to generate evidence pack. Please try again.');
        }
    }

    /**
     * Mark delisting request as submitted and schedule re-checks
     */
    public function submitted(Request $request, Domain $domain)
    {
        // Ensure user owns the domain
        if ($domain->user_id !== Auth::id()) {
            abort(403);
        }

        $request->validate([
            'provider' => 'required|string',
        ]);

        $provider = $request->input('provider');
        $providerMeta = config("rbl.providers.$provider");
        
        if (!$providerMeta) {
            return back()->with('error', 'Invalid RBL provider.');
        }

        // Create incident record for tracking
        Incident::create([
            'domain_id' => $domain->id,
            'kind' => 'rbl_delist_submitted',
            'severity' => 'info',
            'message' => "Delist request submitted to {$providerMeta['name']}",
            'context' => [
                'provider' => $provider,
                'provider_name' => $providerMeta['name'],
                'delist_url' => $providerMeta['delist_url'],
                'submitted_at' => now()->toISOString(),
            ],
        ]);

        // Schedule automatic re-checks
        try {
            // Check in 30 minutes
            dispatch(new \App\Jobs\RunBlacklistScan($domain->id))
                ->delay(now()->addMinutes(30));
            
            // Check in 24 hours
            dispatch(new \App\Jobs\RunBlacklistScan($domain->id))
                ->delay(now()->addDay());
                
            // Check in 7 days (some providers take longer)
            dispatch(new \App\Jobs\RunBlacklistScan($domain->id))
                ->delay(now()->addDays(7));
        } catch (\Exception $e) {
            // Log the error but don't fail the request
            logger()->error('Failed to schedule blacklist re-checks', [
                'domain_id' => $domain->id,
                'provider' => $provider,
                'error' => $e->getMessage(),
            ]);
        }

        return back()->with('status', "Delist request logged for {$providerMeta['name']}. We will automatically re-check your blacklist status in 30 minutes, 24 hours, and 7 days.");
    }

    /**
     * Manually trigger a blacklist re-check
     */
    public function recheck(Domain $domain)
    {
        // Ensure user owns the domain
        if ($domain->user_id !== Auth::id()) {
            abort(403);
        }

        try {
            dispatch(new \App\Jobs\RunBlacklistScan($domain->id));
            
            return back()->with('status', 'Blacklist re-check started. Results will be available shortly.');
        } catch (\Exception $e) {
            logger()->error('Failed to start blacklist re-check', [
                'domain_id' => $domain->id,
                'error' => $e->getMessage(),
            ]);
            
            return back()->with('error', 'Failed to start blacklist re-check. Please try again.');
        }
    }
}
