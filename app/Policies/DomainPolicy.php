<?php

namespace App\Policies;

use App\Models\Domain;
use App\Models\User;
use Illuminate\Auth\Access\HandlesAuthorization;

class DomainPolicy
{
    use HandlesAuthorization;

    /**
     * Determine whether the user can view the domain.
     */
    public function view(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    /**
     * Determine whether the user can update the domain.
     */
    public function update(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    /**
     * Determine whether the user can delete the domain.
     */
    public function delete(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    /**
     * Determine whether the user can scan the domain.
     */
    public function scan(User $user, Domain $domain): bool
    {
        return $user->id === $domain->user_id;
    }

    /**
     * Determine whether the user can run blacklist checks.
     * This is plan-gated - only available for paid plans.
     */
    public function blacklist(User $user, Domain $domain): bool
    {
        // First check if user owns the domain
        if ($user->id !== $domain->user_id) {
            return false;
        }

        // Check if user has a paid plan (not freemium)
        $currentPlan = $user->currentPlan();
        return $currentPlan && $currentPlan->name !== 'freemium';
    }
}
