<?php

namespace App\Observers;

use App\Models\Plan;
use Laravel\Cashier\Subscription;
use Illuminate\Support\Facades\Log;

class CashierSubscriptionObserver
{
    /**
     * Handle the Subscription "creating" event.
     * This runs BEFORE Cashier creates the subscription in the database.
     */
    public function creating(Subscription $subscription): void
    {
        Log::info('CashierSubscriptionObserver: creating event fired', [
            'stripe_id' => $subscription->stripe_id,
            'stripe_price' => $subscription->stripe_price,
            'user_id' => $subscription->user_id,
        ]);

        // Determine plan_id from stripe_price
        $planId = $this->determinePlanIdFromStripePrice($subscription->stripe_price);
        
        if ($planId) {
            $subscription->plan_id = $planId;
            Log::info('CashierSubscriptionObserver: Set plan_id', [
                'plan_id' => $planId,
                'stripe_price' => $subscription->stripe_price,
            ]);
        } else {
            Log::warning('CashierSubscriptionObserver: Could not determine plan_id', [
                'stripe_price' => $subscription->stripe_price,
            ]);
        }
    }

    /**
     * Handle the Subscription "created" event.
     * This runs AFTER Cashier creates the subscription.
     */
    public function created(Subscription $subscription): void
    {
        Log::info('CashierSubscriptionObserver: created event fired', [
            'id' => $subscription->id,
            'stripe_id' => $subscription->stripe_id,
            'plan_id' => $subscription->plan_id,
            'user_id' => $subscription->user_id,
        ]);

        // Backfill plan_id if it wasn't set during creation
        if (!$subscription->plan_id && $subscription->stripe_price) {
            $planId = $this->determinePlanIdFromStripePrice($subscription->stripe_price);
            if ($planId) {
                $subscription->update(['plan_id' => $planId]);
                Log::info('CashierSubscriptionObserver: Backfilled plan_id', [
                    'subscription_id' => $subscription->id,
                    'plan_id' => $planId,
                ]);
            }
        }
    }

    /**
     * Handle the Subscription "updating" event.
     */
    public function updating(Subscription $subscription): void
    {
        // If plan_id is still null and we have a stripe_price, try to set it
        if (!$subscription->plan_id && $subscription->stripe_price) {
            $planId = $this->determinePlanIdFromStripePrice($subscription->stripe_price);
            if ($planId) {
                $subscription->plan_id = $planId;
                Log::info('CashierSubscriptionObserver: Set plan_id during update', [
                    'subscription_id' => $subscription->id,
                    'plan_id' => $planId,
                ]);
            }
        }
    }

    /**
     * Determine plan_id from Stripe price ID.
     */
    private function determinePlanIdFromStripePrice(?string $stripePriceId): ?int
    {
        if (!$stripePriceId) {
            return null;
        }

        // Map Stripe price IDs to plan names
        $priceIdToPlanName = [
            config('services.plans.premium_monthly') => 'Premium',
            config('services.plans.ultra_monthly') => 'Ultra',
            config('services.plans.premium_yearly') => 'Premium',
            config('services.plans.ultra_yearly') => 'Ultra',
            // Add the actual price ID from the failed subscription
            'price_1S8DBWF7L7sj9TWCflaUSEjd' => 'Premium',
        ];

        $planName = $priceIdToPlanName[$stripePriceId] ?? null;
        
        if (!$planName) {
            Log::warning('CashierSubscriptionObserver: Unknown Stripe price ID', [
                'stripe_price_id' => $stripePriceId,
            ]);
            return null;
        }

        // Find the plan by name
        $plan = Plan::where('name', $planName)->where('active', true)->first();
        
        if (!$plan) {
            Log::warning('CashierSubscriptionObserver: Plan not found', [
                'plan_name' => $planName,
                'stripe_price_id' => $stripePriceId,
            ]);
            return null;
        }

        return $plan->id;
    }
}
