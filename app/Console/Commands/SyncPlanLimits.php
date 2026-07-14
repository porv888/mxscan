<?php

namespace App\Console\Commands;

use App\Models\Plan;
use App\Models\User;
use App\Services\Entitlement\EntitlementService;
use Illuminate\Console\Command;

class SyncPlanLimits extends Command
{
    protected $signature = 'plans:sync-limits';

    protected $description = 'Sync Freemium plan domain limit to 1 and report multi-domain free accounts';

    public function handle(EntitlementService $entitlements): int
    {
        $updated = Plan::where('name', 'Freemium')->update(['domain_limit' => 1]);
        $this->info("Updated {$updated} Freemium plan row(s) to domain_limit=1.");

        $freeUsers = User::query()
            ->whereDoesntHave('subscriptions', function ($q) {
                $q->where('status', 'active')
                    ->whereNull('canceled_at')
                    ->whereHas('plan', function ($planQ) {
                        $planQ->whereIn('name', ['Premium', 'Ultra']);
                    });
            })
            ->withCount('domains')
            ->having('domains_count', '>', 1)
            ->get();

        if ($freeUsers->isEmpty()) {
            $this->info('No free accounts with more than one domain.');
            return self::SUCCESS;
        }

        $this->warn('Free accounts with multiple domains (oldest domain remains active):');
        foreach ($freeUsers as $user) {
            $activeId = $entitlements->activeDomainId($user);
            $activeDomain = $user->domains()->where('id', $activeId)->value('domain');
            $this->line("  user_id={$user->id} email={$user->email} domains={$user->domains_count} active={$activeDomain} (id={$activeId})");
        }

        return self::SUCCESS;
    }
}
