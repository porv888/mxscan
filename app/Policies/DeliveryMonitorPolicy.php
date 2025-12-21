<?php

namespace App\Policies;

use App\Models\DeliveryMonitor;
use App\Models\User;

class DeliveryMonitorPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return true;
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, DeliveryMonitor $monitor): bool
    {
        return $user->id === $monitor->user_id;
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return true;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, DeliveryMonitor $monitor): bool
    {
        return $user->id === $monitor->user_id;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, DeliveryMonitor $monitor): bool
    {
        return $user->id === $monitor->user_id;
    }
}
