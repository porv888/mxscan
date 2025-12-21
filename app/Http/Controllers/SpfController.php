<?php

namespace App\Http\Controllers;

use App\Jobs\RunSpfCheck;
use App\Models\Domain;
use App\Models\SpfCheck;
use App\Services\Spf\SpfResolver;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class SpfController extends Controller
{
    /**
     * Display SPF analysis for a domain.
     */
    public function show(string $domain)
    {
        // Find the domain and ensure user owns it
        $domainModel = Domain::where('domain', $domain)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        // Get latest SPF check
        $latestCheck = $domainModel->spfChecks()
            ->orderBy('created_at', 'desc')
            ->first();

        // Get SPF check history (last 10)
        $history = $domainModel->spfChecks()
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        return view('domains.spf', compact('domainModel', 'latestCheck', 'history'));
    }

    /**
     * Run SPF check for a domain.
     */
    public function run(Request $request, string $domain, SpfResolver $spfResolver)
    {
        // Find the domain and ensure user owns it
        $domainModel = Domain::where('domain', $domain)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $user = Auth::user();
        
        // Plan gating: Check if user can run SPF checks
        if (!$this->canRunSpfCheck($user)) {
            return response()->json([
                'error' => 'Daily SPF checks limit reached for your plan. Upgrade to Premium for unlimited checks.'
            ], 429);
        }

        // Rate limiting: Prevent spam
        $rateLimitKey = "spf-check:{$user->id}";
        if (RateLimiter::tooManyAttempts($rateLimitKey, 10)) {
            $seconds = RateLimiter::availableIn($rateLimitKey);
            return response()->json([
                'error' => "Too many requests. Please try again in {$seconds} seconds."
            ], 429);
        }

        RateLimiter::hit($rateLimitKey, 60); // 1 minute window

        // Check if we should run sync or async
        $runSync = config('queue.default') === 'sync' || $request->boolean('sync', false);

        try {
            if ($runSync) {
                // Run synchronously for immediate results
                $result = $spfResolver->resolve($domainModel->domain);
                
                // Get previous check for comparison
                $previousCheck = $domainModel->latestSpfCheck;
                $changed = $previousCheck ? ($previousCheck->flattened_suggestion !== $result->flattenedSpf) : true;
                
                // Create new SPF check record
                $spfCheck = SpfCheck::create([
                    'domain_id' => $domainModel->id,
                    'looked_up_record' => $result->currentRecord,
                    'lookup_count' => $result->lookupsUsed,
                    'warnings' => $result->warnings,
                    'flattened_suggestion' => $result->flattenedSpf,
                    'resolved_ips' => $result->resolvedIps,
                    'changed' => $changed,
                ]);

                // Update domain's cached lookup count
                $domainModel->updateSpfLookupCount($result->lookupsUsed);

                // Increment daily usage counter
                $this->incrementDailyUsage($user);

                if ($request->expectsJson()) {
                    return response()->json([
                        'status' => 'completed',
                        'lookupCount' => $result->lookupsUsed,
                        'warnings' => $result->warnings,
                        'flattened' => $result->flattenedSpf,
                        'resolvedIps' => $result->resolvedIps,
                        'changed' => $changed
                    ]);
                }

                return redirect()
                    ->route('spf.show', $domain)
                    ->with('success', 'SPF check completed successfully!');
            } else {
                // Run asynchronously
                RunSpfCheck::dispatch($domainModel->id);
                
                // Increment daily usage counter
                $this->incrementDailyUsage($user);

                if ($request->expectsJson()) {
                    return response()->json([
                        'status' => 'queued',
                        'message' => 'SPF check is running in the background.'
                    ]);
                }

                return redirect()
                    ->route('spf.show', $domain)
                    ->with('info', 'SPF check is running in the background. Please refresh in a moment.');
            }
        } catch (\Exception $e) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'SPF check failed: ' . $e->getMessage()
                ], 500);
            }

            return redirect()
                ->route('spf.show', $domain)
                ->with('error', 'SPF check failed. Please try again.');
        }
    }

    /**
     * Get SPF check history for a domain.
     */
    public function history(Request $request, string $domain)
    {
        // Find the domain and ensure user owns it
        $domainModel = Domain::where('domain', $domain)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $page = $request->get('page', 1);
        $limit = min($request->get('limit', 20), 100); // Max 100 per page

        $history = $domainModel->spfChecks()
            ->orderBy('created_at', 'desc')
            ->paginate($limit, ['*'], 'page', $page);

        if ($request->expectsJson()) {
            return response()->json($history);
        }

        return view('domains.spf-history', compact('domainModel', 'history'));
    }

    /**
     * Check if user can run SPF checks based on their plan.
     */
    private function canRunSpfCheck($user): bool
    {
        $plan = $user->currentPlan();
        
        if (!$plan || $plan->name === 'freemium') {
            // Freemium: 5 checks per day
            $dailyUsage = $this->getDailyUsage($user);
            return $dailyUsage < 5;
        }
        
        // Premium/Ultra: unlimited
        return true;
    }

    /**
     * Get daily SPF check usage for a user.
     */
    private function getDailyUsage($user): int
    {
        $cacheKey = "spf_daily_usage:{$user->id}:" . now()->format('Y-m-d');
        return Cache::get($cacheKey, 0);
    }

    /**
     * Increment daily SPF check usage for a user.
     */
    private function incrementDailyUsage($user): void
    {
        $cacheKey = "spf_daily_usage:{$user->id}:" . now()->format('Y-m-d');
        $ttl = now()->endOfDay()->diffInSeconds(); // Expire at end of day
        Cache::put($cacheKey, $this->getDailyUsage($user) + 1, $ttl);
    }
}
