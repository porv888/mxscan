<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Models\Plan;
use App\Models\CashierSubscription;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Stripe\Stripe;
use Stripe\Subscription as StripeSubscription;

class FixUserSubscription extends Command
{
    protected $signature = 'subscription:fix {user_id}';
    protected $description = 'Fix subscription for a user by fetching from Stripe and creating local record';

    public function handle()
    {
        $userId = $this->argument('user_id');
        $user = User::find($userId);

        if (!$user) {
            $this->error("User {$userId} not found.");
            return 1;
        }

        $this->info("Fixing subscription for user: {$user->email} (ID: {$user->id})");

        // Set Stripe API key
        Stripe::setApiKey(config('services.stripe.secret'));

        if (!$user->stripe_id) {
            $this->error("User has no Stripe customer ID.");
            return 1;
        }

        $this->info("Stripe Customer ID: {$user->stripe_id}");

        try {
            // Fetch subscriptions from Stripe
            $stripeSubscriptions = StripeSubscription::all([
                'customer' => $user->stripe_id,
                'limit' => 10,
            ]);

            if (count($stripeSubscriptions->data) === 0) {
                $this->warn("No subscriptions found in Stripe for this customer.");
                return 0;
            }

            $this->info("Found " . count($stripeSubscriptions->data) . " subscription(s) in Stripe.");

            foreach ($stripeSubscriptions->data as $stripeSub) {
                $this->line("");
                $this->info("Processing Stripe Subscription: {$stripeSub->id}");
                $this->line("  Status: {$stripeSub->status}");
                $this->line("  Created: " . date('Y-m-d H:i:s', $stripeSub->created));

                // Check if already exists locally
                $existing = CashierSubscription::where('stripe_id', $stripeSub->id)->first();
                if ($existing) {
                    $this->warn("  Subscription already exists locally (ID: {$existing->id})");
                    
                    // Update plan_id if missing
                    if (!$existing->plan_id) {
                        $planId = $this->determinePlanId($stripeSub);
                        if ($planId) {
                            $existing->update(['plan_id' => $planId]);
                            $this->info("  Updated plan_id to: {$planId}");
                        }
                    }
                    continue;
                }

                // Determine plan_id
                $planId = $this->determinePlanId($stripeSub);
                if (!$planId) {
                    $this->warn("  Could not determine plan_id, skipping...");
                    continue;
                }

                // Create local subscription
                $subscription = CashierSubscription::create([
                    'user_id' => $user->id,
                    'type' => 'default',
                    'stripe_id' => $stripeSub->id,
                    'stripe_status' => $stripeSub->status,
                    'stripe_price' => $stripeSub->items->data[0]->price->id ?? null,
                    'quantity' => $stripeSub->items->data[0]->quantity ?? 1,
                    'trial_ends_at' => $stripeSub->trial_end ? date('Y-m-d H:i:s', $stripeSub->trial_end) : null,
                    'ends_at' => $stripeSub->status === 'canceled' && $stripeSub->current_period_end ? 
                        date('Y-m-d H:i:s', $stripeSub->current_period_end) : null,
                    'plan_id' => $planId,
                    'status' => $this->mapStripeStatus($stripeSub->status),
                    'started_at' => date('Y-m-d H:i:s', $stripeSub->created),
                    'expires_at' => date('Y-m-d H:i:s', $stripeSub->current_period_end),
                    'renews_at' => date('Y-m-d H:i:s', $stripeSub->current_period_end),
                ]);

                $this->info("  ✓ Created local subscription (ID: {$subscription->id})");
                $this->line("  Plan ID: {$planId}");
                $this->line("  Status: {$subscription->status}");
            }

            $this->line("");
            $this->info("✓ Subscription fix completed successfully!");
            return 0;

        } catch (\Exception $e) {
            $this->error("Error: " . $e->getMessage());
            Log::error('Subscription fix failed', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return 1;
        }
    }

    private function determinePlanId($stripeSubscription): ?int
    {
        $item = $stripeSubscription->items->data[0] ?? null;
        if (!$item) {
            return null;
        }

        $priceId = $item->price->id ?? null;
        if (!$priceId) {
            return null;
        }

        $this->line("  Stripe Price ID: {$priceId}");

        // Map price ID to plan name
        $priceIdToPlanName = [
            config('services.plans.premium_monthly') => 'Premium',
            config('services.plans.ultra_monthly') => 'Ultra',
            config('services.plans.premium_yearly') => 'Premium',
            config('services.plans.ultra_yearly') => 'Ultra',
        ];

        $planName = $priceIdToPlanName[$priceId] ?? null;
        if (!$planName) {
            $this->warn("  Unknown price ID: {$priceId}");
            return null;
        }

        $plan = Plan::where('name', $planName)->where('active', true)->first();
        if (!$plan) {
            $this->warn("  Plan not found: {$planName}");
            return null;
        }

        return $plan->id;
    }

    private function mapStripeStatus(string $stripeStatus): string
    {
        return match($stripeStatus) {
            'active' => 'active',
            'trialing' => 'trial',
            'canceled' => 'canceled',
            'incomplete', 'incomplete_expired', 'past_due', 'unpaid' => 'expired',
            default => 'canceled'
        };
    }
}
