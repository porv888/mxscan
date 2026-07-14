<?php

namespace App\Services\Entitlement;

use App\Models\Domain;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Centralized plan entitlement evaluator.
 *
 * Free-plan active domain selection (no migration):
 * 1. Future: users.free_active_domain_id if added
 * 2. Otherwise oldest domains.created_at ASC, tie-breaker lowest domains.id
 */
class EntitlementService
{
    /** @var array<int, int|null> */
    protected array $activeDomainIdCache = [];

    public function planKey(User $user): string
    {
        return $user->currentPlanKey();
    }

    public function isPaid(User $user): bool
    {
        return in_array($this->planKey($user), ['premium', 'ultra'], true);
    }

    public function domainLimit(User $user): int
    {
        $plan = $user->currentPlan();
        if ($plan && $plan->domain_limit !== null) {
            return (int) $plan->domain_limit;
        }

        return (int) (config('plans.limits.' . $this->planKey($user)) ?? 1);
    }

    public function domainsUsed(User $user): int
    {
        return $user->domains()->count();
    }

    public function canAddDomain(User $user): bool
    {
        return $this->domainsUsed($user) < $this->domainLimit($user);
    }

    /**
     * The single active domain id for a free user, or null when none exist.
     */
    public function activeDomainId(User $user): ?int
    {
        if (isset($this->activeDomainIdCache[$user->id])) {
            return $this->activeDomainIdCache[$user->id];
        }

        if ($this->isPaid($user)) {
            $this->activeDomainIdCache[$user->id] = null;
            return null;
        }

        $id = $user->domains()
            ->orderBy('created_at')
            ->orderBy('id')
            ->value('id');

        $this->activeDomainIdCache[$user->id] = $id ? (int) $id : null;

        return $this->activeDomainIdCache[$user->id];
    }

    public function isDomainActive(User $user, Domain $domain): bool
    {
        if ($domain->user_id !== $user->id) {
            return false;
        }

        if ($this->isPaid($user)) {
            return true;
        }

        $activeId = $this->activeDomainId($user);

        return $activeId !== null && (int) $domain->id === $activeId;
    }

    public function isDomainLocked(User $user, Domain $domain): bool
    {
        if ($domain->user_id !== $user->id) {
            return true;
        }

        if ($this->isPaid($user)) {
            return false;
        }

        return !$this->isDomainActive($user, $domain);
    }

    public function can(User $user, string $feature): bool
    {
        if ($user->isAdmin()) {
            return true;
        }

        $plan = $this->planKey($user);
        $paid = in_array($plan, ['premium', 'ultra'], true);

        return match ($feature) {
            EntitlementFeature::DOMAIN_CREATE => $this->canAddDomain($user),
            EntitlementFeature::MANUAL_FULL_SCAN => true,
            EntitlementFeature::PARTIAL_SCAN,
            EntitlementFeature::STANDALONE_TOOLS,
            EntitlementFeature::DOMAIN_SPF_ANALYZER,
            EntitlementFeature::AUTOMATIONS,
            EntitlementFeature::SCHEDULED_SCANS,
            EntitlementFeature::MONITORING,
            EntitlementFeature::DELIVERY_MONITORING,
            EntitlementFeature::DMARC_ACTIVITY,
            EntitlementFeature::REPORT_EXPORT,
            EntitlementFeature::NOTIFICATION_INTEGRATIONS,
            EntitlementFeature::EXPIRY_ALERTS => $paid,
            EntitlementFeature::API_ACCESS => $plan === 'ultra',
            default => false,
        };
    }

    public function canOnDomain(User $user, Domain $domain, string $feature): bool
    {
        if ($domain->user_id !== $user->id) {
            return false;
        }

        if ($user->isAdmin()) {
            return true;
        }

        if (in_array($feature, [
            EntitlementFeature::DOMAIN_MANAGE,
            EntitlementFeature::DOMAIN_ACTIVE,
            EntitlementFeature::MANUAL_FULL_SCAN,
            EntitlementFeature::PARTIAL_SCAN,
            EntitlementFeature::SCHEDULED_SCANS,
        ], true) && $this->isDomainLocked($user, $domain)) {
            return false;
        }

        return $this->can($user, $feature);
    }

    public function upgradeUrl(): string
    {
        return route('pricing');
    }

    public function denyMessage(string $feature): string
    {
        return match ($feature) {
            EntitlementFeature::DOMAIN_CREATE,
            EntitlementFeature::DOMAIN_ACTIVE,
            EntitlementFeature::DOMAIN_MANAGE => 'Your Free plan supports one active domain. Upgrade to reactivate this domain.',
            EntitlementFeature::MANUAL_FULL_SCAN => 'This domain is locked on your current plan. Upgrade to run new scans.',
            EntitlementFeature::PARTIAL_SCAN => 'Individual scan modes require a paid plan.',
            EntitlementFeature::STANDALONE_TOOLS => 'Standalone tools require a paid plan.',
            EntitlementFeature::AUTOMATIONS,
            EntitlementFeature::SCHEDULED_SCANS => 'Automations and scheduled scans require a paid plan.',
            EntitlementFeature::MONITORING => 'Monitoring requires a paid plan.',
            EntitlementFeature::DELIVERY_MONITORING => 'Delivery monitoring requires a paid plan.',
            EntitlementFeature::DMARC_ACTIVITY => 'DMARC Activity requires a paid plan.',
            EntitlementFeature::REPORT_EXPORT => 'Report exports require a paid plan.',
            EntitlementFeature::NOTIFICATION_INTEGRATIONS => 'Notification integrations require a paid plan.',
            EntitlementFeature::API_ACCESS => 'API access requires an Ultra plan.',
            default => 'Upgrade required for this feature.',
        };
    }

    public function deny(Request $request, string $feature, int $status = Response::HTTP_PAYMENT_REQUIRED): Response
    {
        $message = $this->denyMessage($feature);
        $payload = [
            'error' => 'Upgrade required',
            'feature' => $feature,
            'message' => $message,
            'upgrade_url' => $this->upgradeUrl(),
        ];

        if ($request->expectsJson()) {
            return response()->json($payload, $status);
        }

        return redirect()
            ->route('pricing')
            ->with('error', $message);
    }
}
