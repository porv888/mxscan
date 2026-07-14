<?php

namespace App\Policies;

use App\Models\Domain;
use App\Models\User;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Illuminate\Auth\Access\HandlesAuthorization;

class DomainPolicy
{
    use HandlesAuthorization;

    public function __construct(
        protected EntitlementService $entitlements
    ) {
    }

    public function view(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    public function update(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id
            && $this->entitlements->canOnDomain($user, $domain, EntitlementFeature::DOMAIN_MANAGE);
    }

    public function delete(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    public function scan(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id
            && $this->entitlements->canOnDomain($user, $domain, EntitlementFeature::MANUAL_FULL_SCAN);
    }

    public function partialScan(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id
            && $this->entitlements->canOnDomain($user, $domain, EntitlementFeature::PARTIAL_SCAN);
    }

    /**
     * Standalone blacklist-only scans (not the blacklist section of a full scan).
     */
    public function blacklist(User $user, Domain $domain): bool
    {
        return $this->partialScan($user, $domain);
    }
}
