<?php

namespace App\Http\Controllers\Billing;

use App\Http\Controllers\Controller;
use App\Models\Plan;
use App\Models\Subscription;
use Illuminate\Http\Request;

class PlanController extends Controller
{
    public function pricing()
    {
        $dbPlans = Plan::where('active', true)->orderBy('domain_limit')->get();
        
        $plans = $dbPlans->map(function ($plan) {
            return [
                'id' => $plan->id,
                'name' => $plan->name,
                'key' => strtolower($plan->name),
                'limit' => $plan->domain_limit,
                'price' => $plan->price,
                'currency' => $plan->currency,
                'interval' => $plan->interval,
                'has_monthly' => true,
                'has_yearly' => false,
            ];
        });
        
        $enableYearly = false;
        
        return view('billing.pricing', compact('plans', 'enableYearly'));
    }

    public function change(Request $request)
    {
        $request->validate(['plan_id' => 'required|exists:plans,id']);
        $plan = Plan::findOrFail($request->plan_id);
        $user = $request->user();

        // If user has more domains than new limit, block downgrade:
        $used = $user->domainsUsed();
        if ($used > $plan->domain_limit) {
            return back()->withErrors([
                'plan' => "You currently have $used domains; the {$plan->name} plan allows {$plan->domain_limit}. Remove domains or choose a higher plan."
            ]);
        }

        // For now, mark as active subscription without payment flow
        // (later: create checkout session & handle webhook)
        $sub = $user->currentSubscription();
        if (!$sub) {
            $sub = new Subscription([
                'status' => 'active',
                'started_at' => now(),
            ]);
            $sub->user()->associate($user);
        }
        $sub->plan()->associate($plan);
        $sub->status = 'active';
        $sub->expires_at = now()->addMonth();
        $sub->save();

        return redirect()->route('profile.show')->with('success', "You are now on the {$plan->name} plan.");
    }
}
