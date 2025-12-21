<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Subscription extends Model
{
    // Use the renamed table to avoid conflict with Laravel Cashier's `subscriptions` table
    protected $table = 'app_subscriptions';

    protected $fillable = [
        'user_id',
        'plan_id',
        'status',
        'started_at',
        'expires_at',
        'renews_at',
        'canceled_at',
        'scans_used',
        'usage_reset_at',
        'notes',
        'stripe_id',
        'stripe_status',
        'stripe_price',
        'quantity',
        'trial_ends_at',
        'ends_at',
        'type',
    ];

    protected $casts = [
        'started_at' => 'datetime',
        'expires_at' => 'datetime',
        'renews_at' => 'datetime',
        'canceled_at' => 'datetime',
        'usage_reset_at' => 'datetime',
        'trial_ends_at' => 'datetime',
        'ends_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function plan(): BelongsTo
    {
        return $this->belongsTo(Plan::class);
    }

    /**
     * Scope for active subscriptions
     */
    public function scopeActive($query)
    {
        return $query->where('status', 'active');
    }
}
