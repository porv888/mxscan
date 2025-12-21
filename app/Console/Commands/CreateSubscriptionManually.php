<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Models\Plan;
use App\Models\CashierSubscription;
use Illuminate\Console\Command;

class CreateSubscriptionManually extends Command
{
    protected $signature = 'subscription:create-manual {user_id} {stripe_subscription_id} {plan_name}';
    protected $description = 'Manually create a subscription record';

    public function handle()
    {
        $userId = $this->argument('user_id');
        $stripeSubId = $this->argument('stripe_subscription_id');
        $planName = $this->argument('plan_name');

        $user = User::find($userId);
        if (!$user) {
            $this->error("User {$userId} not found.");
            return 1;
        }

        $plan = Plan::where('name', $planName)->where('active', true)->first();
        if (!$plan) {
            $this->error("Plan '{$planName}' not found.");
            return 1;
        }

        // Check if subscription already exists
        $existing = CashierSubscription::where('stripe_id', $stripeSubId)->first();
        if ($existing) {
            $this->warn("Subscription already exists (ID: {$existing->id})");
            
            // Update it
            $existing->update([
                'plan_id' => $plan->id,
                'status' => 'active',
                'stripe_status' => 'active',
            ]);
            
            $this->info("Updated subscription ID: {$existing->id}");
            return 0;
        }

        // Create new subscription
        $subscription = CashierSubscription::create([
            'user_id' => $user->id,
            'type' => 'default',
            'stripe_id' => $stripeSubId,
            'stripe_status' => 'active',
            'stripe_price' => 'price_1S8DBWF7L7sj9TWCflaUSEjd',
            'quantity' => 1,
            'plan_id' => $plan->id,
            'status' => 'active',
            'started_at' => now(),
            'expires_at' => now()->addMonth(),
            'renews_at' => now()->addMonth(),
        ]);

        $this->info("✓ Subscription created successfully!");
        $this->line("  ID: {$subscription->id}");
        $this->line("  User: {$user->email}");
        $this->line("  Plan: {$plan->name}");
        $this->line("  Stripe ID: {$stripeSubId}");

        return 0;
    }
}
