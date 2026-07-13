<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\Schedule;
use App\Models\DeliveryMonitor;
use App\Models\Scan;
use App\Jobs\RunFullScan;
use App\Rules\WithinDomainLimit;
use App\Support\DomainNormalizer;
use App\Services\Dmarc\DmarcAnalyticsService;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\Expiry\ExpiryCoordinator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class DomainController extends Controller
{
    /**
     * Display a listing of the user's domains.
     */
    public function index()
    {
        $domains = Domain::where('user_id', Auth::id())
            ->with('activeSchedule')
            ->orderBy('created_at', 'desc')
            ->get();

        $analytics = app(DmarcAnalyticsService::class);
        $statusService = app(DmarcStatusService::class);
        $dmarcSummaries = [];

        foreach ($domains as $domain) {
            $summary = $analytics->getDomainSummary($domain, 7);
            $status = $statusService->getStatus($domain);
            $dmarcSummaries[$domain->id] = [
                'summary' => $summary,
                'status' => $status,
            ];
        }

        return view('domains.index', compact('domains', 'dmarcSummaries'));
    }

    /**
     * Show the form for creating a new domain.
     */
    public function create()
    {
        return view('domains.create');
    }

    /**
     * Store a newly created domain in storage.
     */
    public function store(Request $request)
    {
        $normalized = DomainNormalizer::normalize((string) $request->input('domain', ''));
        if ($normalized !== null) {
            $request->merge(['domain' => $normalized]);
        }

        $validated = $request->validate([
            'domain' => [
                'required',
                'string',
                'max:255',
                'regex:/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$/',
                Rule::unique('domains')->where(function ($query) {
                    return $query->where('user_id', Auth::id());
                }),
                new WithinDomainLimit($request->user())
            ],
            'environment' => 'nullable|in:prod,dev',
            'services' => ['nullable', 'array'],
            'services.*' => ['string'],
            'schedule' => ['nullable', 'string'],
        ], [
            'domain.required' => 'Domain name is required.',
            'domain.regex' => 'Please enter a valid domain name (e.g., example.com).',
            'domain.unique' => 'You have already added this domain.',
            'environment.in' => 'Environment must be either Production or Development.'
        ]);

        if ($normalized === null) {
            return redirect()->back()
                ->withInput()
                ->withErrors(['domain' => 'Please enter a valid domain name (e.g., example.com).']);
        }

        $providerGuess = $this->guessProvider($validated['domain']);
        $user = $request->user();
        $environment = $validated['environment'] ?? 'prod';

        try {
            $domain = Domain::create([
                'user_id' => $user->id,
                'domain' => strtolower($validated['domain']),
                'environment' => $environment,
                'provider_guess' => $providerGuess,
                'status' => 'active',
            ]);

            $selected = collect($validated['services'] ?? []);
            $enabledServices = $selected->values()->unique()->intersect([
                'dns', 'blacklist', 'spf', 'delivery', 'domain_expiry', 'ssl_expiry',
            ])->values()->all();

            if (empty($enabledServices)) {
                $enabledServices = ['dns', 'spf', 'blacklist', 'domain_expiry', 'ssl_expiry'];
            }

            $cadRaw = $validated['schedule'] ?? 'off';
            [$cadence, $at] = str_contains($cadRaw, '@') ? explode('@', $cadRaw, 2) : [$cadRaw, null];
            $cadence = in_array($cadence, ['off', 'daily', 'weekly'], true) ? $cadence : 'off';
            $runAt = $at && preg_match('/^\d{2}:\d{2}$/', $at) ? $at . ':00' : null;

            Schedule::create([
                'domain_id' => $domain->id,
                'user_id' => $user->id,
                'scan_type' => 'both',
                'frequency' => $cadence === 'off' ? 'daily' : $cadence,
                'cron_expression' => null,
                'status' => $cadence === 'off' ? 'paused' : 'active',
                'next_run_at' => null,
                'last_run_at' => null,
                'settings' => [
                    'services' => $enabledServices,
                    'run_at' => $runAt,
                ],
            ]);

            if (in_array('delivery', $enabledServices, true)) {
                $token = Str::uuid()->toString();
                $local = 'monitor+' . $token;
                $addr = $local . '@mxscan.me';

                DeliveryMonitor::create([
                    'user_id' => $user->id,
                    'domain_id' => $domain->id,
                    'label' => $domain->domain . ' monitor',
                    'inbox_address' => $addr,
                    'token' => $token,
                    'status' => 'active',
                    'last_check_at' => null,
                    'last_incident_notified_at' => null,
                ]);
            }

            $scan = Scan::create([
                'domain_id' => $domain->id,
                'user_id' => $user->id,
                'type' => 'full',
                'status' => 'queued',
                'progress_pct' => 0,
            ]);

            $scanOptions = [
                'dns' => in_array('dns', $enabledServices, true),
                'spf' => in_array('spf', $enabledServices, true),
                'blacklist' => in_array('blacklist', $enabledServices, true),
                'monitoring' => true,
                'scan_id' => $scan->id,
            ];
            if (!$scanOptions['dns'] && !$scanOptions['spf'] && !$scanOptions['blacklist']) {
                $scanOptions['dns'] = true;
                $scanOptions['spf'] = true;
                $scanOptions['blacklist'] = true;
            }

            RunFullScan::dispatch($domain->id, $scanOptions);

            return redirect()->route('reports.show', $scan)
                ->with('toast', [
                    'type' => 'success',
                    'text' => 'Domain added. Your first scan is starting.',
                ]);
        } catch (\Illuminate\Database\QueryException $e) {
            if ($e->errorInfo[1] == 1062) {
                return redirect()->back()
                                ->withInput()
                                ->withErrors(['domain' => 'You have already added this domain.']);
            }

            throw $e;
        }
    }

    /**
     * Show the form for editing the specified domain.
     */
    public function edit(Domain $domain)
    {
        // Ensure user can only edit their own domains
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        return view('domains.edit', compact('domain'));
    }

    /**
     * Update the specified domain in storage.
     */
    public function update(Request $request, Domain $domain)
    {
        // Ensure user can only update their own domains
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        $validated = $request->validate([
            'domain' => [
                'required',
                'string',
                'max:255',
                'regex:/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/',
                Rule::unique('domains')->where(function ($query) {
                    return $query->where('user_id', Auth::id());
                })->ignore($domain->id)
            ],
            'environment' => 'required|in:prod,dev',
            'domain_expires_at' => 'nullable|date|after:today',
            'ssl_expires_at' => 'nullable|date|after:today',
        ], [
            'domain.required' => 'Domain name is required.',
            'domain.regex' => 'Please enter a valid domain name (e.g., example.com).',
            'domain.unique' => 'You have already added this domain.',
            'environment.required' => 'Environment selection is required.',
            'environment.in' => 'Environment must be either Production or Development.',
            'domain_expires_at.after' => 'Domain expiry date must be in the future.',
            'ssl_expires_at.after' => 'SSL expiry date must be in the future.',
        ]);

        // Update provider guess if domain changed
        if ($domain->domain !== strtolower($validated['domain'])) {
            $validated['provider_guess'] = $this->guessProvider($validated['domain']);
        }

        $domain->update([
            'domain' => strtolower($validated['domain']),
            'environment' => $validated['environment'],
            'provider_guess' => $validated['provider_guess'] ?? $domain->provider_guess,
            'domain_expires_at' => $validated['domain_expires_at'] ?? null,
            'ssl_expires_at' => $validated['ssl_expires_at'] ?? null,
        ]);

        return redirect()->route('dashboard.domains')
                        ->with('success', 'Domain updated successfully!');
    }

    /**
     * Remove the specified domain from storage.
     */
    public function destroy(Domain $domain)
    {
        // Ensure user can only delete their own domains
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        $domainName = $domain->domain;
        $domain->delete();

        return redirect()->route('dashboard.domains')
                        ->with('success', "Domain '{$domainName}' has been deleted successfully.");
    }

    /**
     * Configure scheduled scans for a domain.
     */
    public function schedule(Request $request, Domain $domain)
    {
        // Ensure user can only schedule scans for their own domains
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        $validated = $request->validate([
            'frequency' => 'required|in:disabled,daily,weekly,monthly',
            'scan_types' => 'array',
            'scan_types.*' => 'in:email_security,blacklist_monitoring'
        ]);

        if ($validated['frequency'] === 'disabled') {
            // Delete existing schedules for this domain
            Schedule::where('domain_id', $domain->id)
                   ->where('user_id', Auth::id())
                   ->delete();
            
            return redirect()->route('dashboard.domains')
                           ->with('success', "Scheduled scans disabled for {$domain->domain}");
        }

        // Determine scan type
        $scanTypes = $validated['scan_types'] ?? [];
        $scanType = 'dns_security'; // default
        
        if (in_array('email_security', $scanTypes) && in_array('blacklist_monitoring', $scanTypes)) {
            $scanType = 'both';
        } elseif (in_array('blacklist_monitoring', $scanTypes)) {
            $scanType = 'blacklist';
        }

        // Delete existing schedule and create new one
        Schedule::where('domain_id', $domain->id)
               ->where('user_id', Auth::id())
               ->delete();

        $schedule = new Schedule([
            'domain_id' => $domain->id,
            'user_id' => Auth::id(),
            'scan_type' => $scanType,
            'frequency' => $validated['frequency'],
            'status' => 'active',
        ]);
        
        $schedule->next_run_at = $schedule->calculateNextRun();
        $schedule->save();

        return redirect()->route('schedules.index')
                        ->with('success', "Schedule created for {$domain->domain} - {$schedule->frequency_display} {$schedule->scan_type_display} scans");
    }

    /**
     * Refresh expiry dates for a domain.
     */
    public function refreshExpiry(Domain $domain, ExpiryCoordinator $coordinator)
    {
        // Ensure user can only refresh their own domains
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        try {
            // Run fast-path detection
            $domainResult = $coordinator->detectDomainExpiry($domain, true);
            $sslResult = $coordinator->detectSslExpiry($domain, true);
            
            $coordinator->updateDomain($domain, $domainResult, $sslResult);
            
            $messages = [];
            
            if ($domainResult && $domainResult->isValid()) {
                $messages[] = "Domain expiry detected: " . $domainResult->expiryDate->format('M d, Y');
            } else {
                $messages[] = "Domain expiry: detection failed";
            }
            
            if ($sslResult && $sslResult->isValid()) {
                $messages[] = "SSL expiry detected: " . $sslResult->expiryDate->format('M d, Y');
            } else {
                $messages[] = "SSL expiry: detection failed";
            }
            
            return redirect()->back()->with('status', implode('. ', $messages));
            
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Expiry detection failed: ' . $e->getMessage());
        }
    }

    /**
     * Guess the email provider based on domain name.
     */
    private function guessProvider(string $domain): string
    {
        $domain = strtolower($domain);
        
        $providers = [
            'gmail.com' => 'Google Workspace',
            'googlemail.com' => 'Google Workspace',
            'outlook.com' => 'Microsoft 365',
            'hotmail.com' => 'Microsoft 365',
            'live.com' => 'Microsoft 365',
            'office365.com' => 'Microsoft 365',
            'yahoo.com' => 'Yahoo Mail',
            'protonmail.com' => 'ProtonMail',
            'fastmail.com' => 'FastMail',
            'zoho.com' => 'Zoho Mail'
        ];

        // Check for exact matches
        if (isset($providers[$domain])) {
            return $providers[$domain];
        }

        // Check for common patterns
        if (str_contains($domain, 'google') || str_contains($domain, 'gmail')) {
            return 'Google Workspace';
        }
        
        if (str_contains($domain, 'microsoft') || str_contains($domain, 'outlook') || str_contains($domain, 'office365')) {
            return 'Microsoft 365';
        }

        if (str_contains($domain, 'yahoo')) {
            return 'Yahoo Mail';
        }

        return 'Custom/Other';
    }
}
