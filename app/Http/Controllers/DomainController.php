<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\Schedule;
use App\Models\DeliveryMonitor;
use App\Rules\WithinDomainLimit;
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
                        ->orderBy('created_at', 'desc')
                        ->get();

        return view('domains.index', compact('domains'));
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
            'environment' => 'required|in:prod,dev',
            'services' => ['array'],
            'services.*' => ['string'],
            'schedule' => ['nullable', 'string'], // "off" or "daily@09:00" / "weekly@09:00"
        ], [
            'domain.required' => 'Domain name is required.',
            'domain.regex' => 'Please enter a valid domain name (e.g., example.com).',
            'domain.unique' => 'You have already added this domain.',
            'environment.required' => 'Environment selection is required.',
            'environment.in' => 'Environment must be either Production or Development.'
        ]);

        // Guess provider based on domain
        $providerGuess = $this->guessProvider($validated['domain']);
        $user = $request->user();

        try {
            $domain = Domain::create([
                'user_id' => $user->id,
                'domain' => strtolower($validated['domain']),
                'environment' => $validated['environment'],
                'provider_guess' => $providerGuess,
                'status' => 'active',
            ]);

            // Normalize service selections
            $selected = collect($validated['services'] ?? []);
            $enabledServices = $selected->values()->unique()->intersect(['dns', 'blacklist', 'spf', 'delivery'])->all();
            
            // Default to dns, spf, blacklist if nothing selected
            if (empty($enabledServices)) {
                $enabledServices = ['dns', 'spf', 'blacklist'];
            }

            // Parse cadence
            $cadRaw = $validated['schedule'] ?? 'off';
            [$cadence, $at] = str_contains($cadRaw, '@') ? explode('@', $cadRaw, 2) : [$cadRaw, null];
            $cadence = in_array($cadence, ['off', 'daily', 'weekly'], true) ? $cadence : 'off';
            $runAt = $at && preg_match('/^\d{2}:\d{2}$/', $at) ? $at . ':00' : null;

            // Persist schedule using existing schedules table
            // Note: we keep scan_type='both' to reuse current runner; granular services live in settings JSON
            Schedule::create([
                'domain_id' => $domain->id,
                'user_id' => $user->id,
                'scan_type' => 'both', // do not change enum, reuse it
                'frequency' => $cadence === 'off' ? 'daily' : $cadence, // daily/weekly required by enum
                'cron_expression' => null,
                'status' => $cadence === 'off' ? 'paused' : 'active',
                'next_run_at' => null, // let existing scheduler compute this if you have logic
                'last_run_at' => null,
                'settings' => [
                    'services' => $enabledServices, // <-- the important bit
                    'run_at' => $runAt, // optional HH:MM:SS
                ],
            ]);

            // If Delivery Monitor was enabled, create one monitor row
            if (in_array('delivery', $enabledServices, true)) {
                // Generate unique token/address
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

            return redirect()->route('dashboard.domains')
                            ->with('success', 'Domain added successfully! You can now run a security scan.');
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle any database constraint violations that slip through validation
            if ($e->errorInfo[1] == 1062) { // Duplicate entry error
                return redirect()->back()
                                ->withInput()
                                ->withErrors(['domain' => 'You have already added this domain.']);
            }
            
            // Re-throw other database errors
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
