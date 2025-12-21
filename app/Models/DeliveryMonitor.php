<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DeliveryMonitor extends Model
{
    protected $fillable = [
        'user_id',
        'domain_id',
        'label',
        'inbox_address',
        'token',
        'status',
        'last_check_at',
        'last_incident_notified_at',
    ];

    protected $casts = [
        'last_check_at' => 'datetime',
        'last_incident_notified_at' => 'datetime',
    ];

    /**
     * Get the user that owns the monitor
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the domain associated with this monitor (optional)
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get all delivery checks for this monitor
     */
    public function checks(): HasMany
    {
        return $this->hasMany(DeliveryCheck::class);
    }

    /**
     * Count incidents in the last 7 days
     */
    public function incidentsLast7Days(): int
    {
        return $this->checks()
            ->where('verdict', 'incident')
            ->where('created_at', '>=', now()->subDays(7))
            ->count();
    }

    /**
     * Get the most recent check
     */
    public function latestCheck()
    {
        return $this->checks()->latest('received_at')->first();
    }

    /**
     * Check if monitor is active
     */
    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * Check if monitor is paused
     */
    public function isPaused(): bool
    {
        return $this->status === 'paused';
    }
}
