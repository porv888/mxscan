<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Invoice extends Model
{
    protected $fillable = [
        'user_id',
        'subscription_id',
        'amount',
        'currency',
        'status',
        'payment_provider',
        'provider_reference',
        'provider_data',
        'issued_at',
        'paid_at',
        'due_at',
    ];

    protected $casts = [
        'amount' => 'decimal:2',
        'provider_data' => 'array',
        'issued_at' => 'datetime',
        'paid_at' => 'datetime',
        'due_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function subscription(): BelongsTo
    {
        return $this->belongsTo(Subscription::class);
    }
}
