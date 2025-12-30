<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\StripePriceResolver;
use App\Models\Plan;
use App\Models\Subscription;
use Illuminate\Support\Carbon;
use Stripe\StripeClient;

class BillingController extends Controller
{
    public function show(Request $request)
    {
        $user = $request->user();

        // Resolve price IDs from lookup keys first, fallback to direct env price IDs
        $resolver = new StripePriceResolver();
        $premiumLookup = config('plans.lookup_keys.premium_monthly');
        $ultraLookup   = config('plans.lookup_keys.ultra_monthly');

        $pricePremium = $resolver->resolvePriceIdFromLookup($premiumLookup)
            ?: config('plans.prices.premium_monthly');
        $priceUltra   = $resolver->resolvePriceIdFromLookup($ultraLookup)
            ?: config('plans.prices.ultra_monthly');

        // Fetch dynamic amounts for display (optional; fallback to static if unavailable)
        $displayPremium = '€19';
        $displayUltra   = '€49';
        try {
            if ($meta = $resolver->getAmountCurrencyForLookup($premiumLookup)) {
                [$amount, $currency] = $meta; // amount decimal, currency code
                $displayPremium = $this->formatCurrencyForDisplay($amount, $currency);
            }
            if ($meta = $resolver->getAmountCurrencyForLookup($ultraLookup)) {
                [$amount, $currency] = $meta;
                $displayUltra = $this->formatCurrencyForDisplay($amount, $currency);
            }
        } catch (\Throwable $e) {
            // Non-fatal: keep static fallback amounts
            report($e);
        }

        // Source of truth for UI: internal app subscriptions
        $appPlan         = $user->currentPlan();
        $appSubscription = $user->currentSubscription();
        $planKey         = $user->currentPlanKey(); // freemium | premium | ultra

        // Keep Stripe price IDs available for checkout/swap actions, but do not
        // use Stripe to decide what to display as the current plan on the page.

        // Get domain limits from database
        $plans = \App\Models\Plan::all()->keyBy(fn($p) => strtolower($p->name));
        $freemiumLimit = $plans['freemium']->domain_limit ?? 3;
        $premiumLimit = $plans['premium']->domain_limit ?? 9;
        $ultraLimit = $plans['ultra']->domain_limit ?? 19;

        return view('billing.show', [
            'user'             => $user,
            // Internal subscription/plan data (display)
            'appPlan'          => $appPlan,
            'appSubscription'  => $appSubscription,
            'planKey'          => $planKey,
            // Stripe price IDs (actions)
            'pricePremium'     => $pricePremium,
            'priceUltra'       => $priceUltra,
            'displayPremium'   => $displayPremium,
            'displayUltra'     => $displayUltra,
            // Booleans derived from internal plan
            'onFreemium'       => $planKey === 'freemium',
            'isPremium'        => $planKey === 'premium',
            'isUltra'          => $planKey === 'ultra',
            // Domain limits from database
            'freemiumLimit'    => $freemiumLimit,
            'premiumLimit'     => $premiumLimit,
            'ultraLimit'       => $ultraLimit,
        ]);
    }

    private function formatCurrencyForDisplay(float $amount, string $currency): string
    {
        $currency = strtoupper($currency);
        $decimals = fmod($amount, 1.0) == 0.0 ? 0 : 2;
        $formatted = number_format($amount, $decimals);
        switch ($currency) {
            case 'EUR':
                return "€{$formatted}";
            case 'USD':
                return "
$${formatted}";
            case 'GBP':
                return "£{$formatted}";
            default:
                return "{$currency} {$formatted}";
        }
    }

    /**
     * Start a new subscription using Stripe Checkout.
     * Used when user has NO paid subscription yet (Freemium).
     */
    public function checkout(Request $request)
    {
        // Whitelist allowed Stripe price IDs resolved from lookup keys (fallback to env price IDs)
        $resolver = new StripePriceResolver();
        $allowedPrices = array_values(array_filter([
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.premium_monthly')) ?: config('plans.prices.premium_monthly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.ultra_monthly'))   ?: config('plans.prices.ultra_monthly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.premium_yearly'))  ?: config('plans.prices.premium_yearly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.ultra_yearly'))    ?: config('plans.prices.ultra_yearly'),
        ]));

        $request->validate([
            'price' => ['required','string', function($attr, $value, $fail) use ($allowedPrices) {
                if (! in_array((string) $value, $allowedPrices, true)) {
                    $fail('Invalid price selection.');
                }
            }],
        ]);

        $user  = $request->user();
        $price = (string) $request->input('price');

        // If user already has an active sub, redirect to swap
        if ($user->subscribed('default')) {
            return redirect()->route('billing')->with('error', 'You already have a subscription.');
        }

        try {
            // Remember what price user selected so we can map plan on return
            session()->put('pending_price', $price);
            return $user->newSubscription('default', $price)
                ->checkout([
                    'success_url' => route('billing.success'),
                    'cancel_url'  => route('billing.cancel'),
                ]);
        } catch (\Throwable $e) {
            report($e);
            return back()->with('error', 'Could not start Checkout. Please verify plan selection and try again.');
        }
    }

    /**
     * Swap an existing subscription price with proration.
     * If the user has no default payment method, redirect them to Checkout first.
     */
    public function swap(Request $request)
    {
        // Whitelist allowed Stripe price IDs resolved from lookup keys (fallback to env price IDs)
        $resolver = new StripePriceResolver();
        $allowedPrices = array_values(array_filter([
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.premium_monthly')) ?: config('plans.prices.premium_monthly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.ultra_monthly'))   ?: config('plans.prices.ultra_monthly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.premium_yearly'))  ?: config('plans.prices.premium_yearly'),
            $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.ultra_yearly'))    ?: config('plans.prices.ultra_yearly'),
        ]));

        $request->validate([
            'price' => ['required','string', function($attr, $value, $fail) use ($allowedPrices) {
                if (! in_array((string) $value, $allowedPrices, true)) {
                    $fail('Invalid price selection.');
                }
            }],
        ]);

        $user       = $request->user();
        $newPriceId = (string) $request->input('price');

        $subscription = $user->subscription('default');
        if (! $subscription || ! $subscription->valid()) {
            // No paid sub → go to Checkout to create it
            try {
                session()->put('pending_price', $newPriceId);
                return $user->newSubscription('default', $newPriceId)
                    ->checkout([
                        'success_url' => route('billing.success'),
                        'cancel_url'  => route('billing.cancel'),
                    ]);
            } catch (\Throwable $e) {
                report($e);
                return back()->with('error', 'Could not start Checkout. Please verify plan selection and try again.');
            }
        }

        // If they don't have a default card, use Checkout to collect a PM first
        if (! $user->hasDefaultPaymentMethod()) {
            session()->put('pending_price', $newPriceId);
            return $user->newSubscription('default', $newPriceId)
                ->checkout([
                    'success_url' => route('billing.success'),
                    'cancel_url'  => route('billing.cancel'),
                ]);
        }

        // Swap plan and invoice proration immediately
        try {
            $subscription->swapAndInvoice($newPriceId);
            // Keep internal source of truth in sync
            try {
                $this->syncInternalSubscriptionFromStripe($user, $newPriceId);
            } catch (\Throwable $e) {
                report($e);
            }
            return redirect()->route('billing')->with('status', 'Your plan has been updated.');
        } catch (\Throwable $e) {
            report($e);
            return back()->with('error', 'Could not update plan. Try the billing portal.');
        }
    }

    /**
     * Stripe Billing Portal (change card, view invoices, cancel/resume).
     */
    public function portal(Request $request)
    {
        try {
            return $request->user()->redirectToBillingPortal(route('billing'));
        } catch (\Stripe\Exception\InvalidRequestException $e) {
            // Handle missing Customer Portal configuration
            if (str_contains($e->getMessage(), 'No configuration provided')) {
                return redirect()->route('billing')->with('error', 
                    'The billing portal is currently unavailable. Please contact support for billing assistance at hello@mxscan.me'
                );
            }
            
            // Re-throw other Stripe errors
            throw $e;
        } catch (\Throwable $e) {
            report($e);
            return redirect()->route('billing')->with('error', 
                'Unable to access billing portal. Please try again or contact support.'
            );
        }
    }

    public function success()
    {
        // After returning from Checkout, sync internal subscription so UI reflects the new plan immediately
        try {
            $user = auth()->user();
            if ($user) {
                $hint = session()->pull('pending_price');
                $this->syncInternalSubscriptionFromStripe($user, $hint ? (string)$hint : null);
            }
        } catch (\Throwable $e) {
            report($e);
        }
        return redirect()->route('billing')->with('status', 'Payment successful. Your subscription is active.');
    }

    public function cancel()
    {
        return redirect()->route('billing')->with('error', 'Checkout canceled.');
    }
    /**
     * Sync the app_subscriptions record to match the current Stripe subscription.
     * Source of truth for the UI is internal, so we update it here on success/swap.
     */
    private function syncInternalSubscriptionFromStripe($user, ?string $hintPriceId = null): void
    {
        $cashierSub = $user->subscription('default');

        // If Cashier hasn't synced yet, try Stripe directly
        if (! $cashierSub || ! $cashierSub->valid()) {
            try {
                $stripeId = $user->stripe_id ?? null;
                if (! $stripeId) {
                    return;
                }
                $stripe = new StripeClient(config('services.stripe.secret'));
                // Get the most recent active subscription for this customer
                $subs = $stripe->subscriptions->all([
                    'customer' => $stripeId,
                    'status'   => 'all',
                    'limit'    => 5,
                ])->data;

                $stripeSub = collect($subs)
                    ->filter(function ($s) { return in_array($s->status, ['active','trialing','past_due']); })
                    ->sortByDesc(function ($s) { return $s->current_period_end ?? 0; })
                    ->first();

                if (! $stripeSub) {
                    return; // nothing we can do
                }

                // Build a lightweight object to reuse mapping logic below
                $cashierSub = new class($stripeSub, $stripe) {
                    public $stripeSub; public $client;
                    public function __construct($sub, $client){ $this->stripeSub=$sub; $this->client=$client; }
                    public function valid(){ return in_array($this->stripeSub->status, ['active','trialing','past_due']); }
                    public function asStripeSubscription(){ return $this->stripeSub; }
                    public function stripe(){ return $this->client; }
                };
            } catch (\Throwable $e) {
                // give up quietly; UI will still show freemium until webhook completes
                return;
            }
        }

        // Determine plan from Stripe price ID
        $resolver = new \App\Services\StripePriceResolver();
        $priceId = $hintPriceId ?: (optional($cashierSub->asStripeSubscription()->items->data[0] ?? null)->price->id ?? null);

        // Resolve allowed price IDs from config/lookup for mapping
        $premiumId = $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.premium_monthly'))
            ?: (string) (config('plans.prices.premium_monthly') ?? '');
        $ultraId   = $resolver->resolvePriceIdFromLookup(config('plans.lookup_keys.ultra_monthly'))
            ?: (string) (config('plans.prices.ultra_monthly') ?? '');

        $names = config('plans.names');
        $planName = null;
        if ($priceId && $premiumId && $priceId === (string) $premiumId) {
            $planName = $names['premium'] ?? 'Premium';
        } elseif ($priceId && $ultraId && $priceId === (string) $ultraId) {
            $planName = $names['ultra'] ?? 'Ultra';
        }

        // Additional fallbacks: lookup_key, price nickname, product name, and amount
        if (! $planName) {
            try {
                $stripeSub = $cashierSub->asStripeSubscription();
                $price = $stripeSub->items->data[0]->price ?? null;
                if ($price) {
                    // 1) lookup_key heuristic
                    $lk = strtolower((string) ($price->lookup_key ?? ''));
                    if ($lk) {
                        if (str_contains($lk, 'ultra')) {
                            $planName = $names['ultra'] ?? 'Ultra';
                        } elseif (str_contains($lk, 'premium')) {
                            $planName = $names['premium'] ?? 'Premium';
                        }
                    }

                    // 2) nickname heuristic
                    if (! $planName) {
                        $nickname = strtolower((string) ($price->nickname ?? ''));
                        if (str_contains($nickname, 'ultra')) {
                            $planName = $names['ultra'] ?? 'Ultra';
                        } elseif (str_contains($nickname, 'premium')) {
                            $planName = $names['premium'] ?? 'Premium';
                        }
                    }

                    // 3) product name heuristic
                    if (! $planName) {
                        try {
                            $product = $price->product ? $cashierSub->stripe()->products->retrieve($price->product) : null;
                            $pname = strtolower((string) ($product->name ?? ''));
                            if (str_contains($pname, 'ultra')) {
                                $planName = $names['ultra'] ?? 'Ultra';
                            } elseif (str_contains($pname, 'premium')) {
                                $planName = $names['premium'] ?? 'Premium';
                            }
                        } catch (\Throwable $e) {
                            // ignore
                        }
                    }

                    // 4) amount match heuristic (compare against our Plan prices if set)
                    if (! $planName && isset($price->unit_amount)) {
                        $amountDecimal = ((int) $price->unit_amount) / 100.0;
                        $currency = strtoupper($price->currency ?? '');
                        $premiumPlan = \App\Models\Plan::where('name', $names['premium'] ?? 'Premium')->first();
                        $ultraPlan   = \App\Models\Plan::where('name', $names['ultra'] ?? 'Ultra')->first();
                        if ($premiumPlan && (float) $premiumPlan->price > 0 && abs((float)$premiumPlan->price - $amountDecimal) < 0.01) {
                            $planName = $premiumPlan->name;
                        } elseif ($ultraPlan && (float) $ultraPlan->price > 0 && abs((float)$ultraPlan->price - $amountDecimal) < 0.01) {
                            $planName = $ultraPlan->name;
                        }
                    }
                }
            } catch (\Throwable $e) {
                // ignore any mapping failure, we simply won't sync
            }
        }

        if (! $planName) {
            return; // Can't map price -> internal plan; leave as-is
        }

        $plan = \App\Models\Plan::where('name', $planName)->first();
        if (! $plan) {
            return;
        }

        // Upsert internal subscription
        $appSub = $user->currentSubscription() ?: new \App\Models\Subscription([ 'user_id' => $user->id ]);
        $appSub->plan()->associate($plan);
        $appSub->status = 'active';

        try {
            $stripeSub = $cashierSub->asStripeSubscription();
            $periodEnd = $stripeSub->current_period_end ?? null;
            $periodStart = $stripeSub->current_period_start ?? null;
            if ($periodStart) {
                $appSub->started_at = Carbon::createFromTimestamp($periodStart);
            }
            if ($periodEnd) {
                $appSub->renews_at = Carbon::createFromTimestamp($periodEnd);
                $appSub->expires_at = Carbon::createFromTimestamp($periodEnd);
            }
        } catch (\Throwable $e) {
            // non-fatal, keep timestamps as-is
            \Log::warning('Could not map Stripe period to internal subscription', [ 'user_id' => $user->id, 'error' => $e->getMessage() ]);
        }

        $appSub->save();
    }
}
