<?php

namespace App\Models;

use Laravel\Cashier\Subscription as CashierBaseSubscription;

/**
 * Custom Cashier Subscription model that uses the app_subscriptions table
 * and includes our custom plan_id field.
 */
class CashierSubscription extends CashierBaseSubscription
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'app_subscriptions';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
        'type',
        'stripe_id',
        'stripe_status',
        'stripe_price',
        'quantity',
        'trial_ends_at',
        'ends_at',
        'plan_id', // Our custom field
        'status',
        'started_at',
        'expires_at',
        'renews_at',
        'canceled_at',
        'scans_used',
        'usage_reset_at',
        'notes',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'trial_ends_at' => 'datetime',
        'ends_at' => 'datetime',
        'started_at' => 'datetime',
        'expires_at' => 'datetime',
        'renews_at' => 'datetime',
        'canceled_at' => 'datetime',
        'usage_reset_at' => 'datetime',
    ];

    /**
     * Get the plan associated with the subscription.
     */
    public function plan()
    {
        return $this->belongsTo(Plan::class);
    }
}
