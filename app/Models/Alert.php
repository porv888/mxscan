<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Alert extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'type',
        'meta',
    ];

    protected $casts = [
        'meta' => 'array',
    ];

    /**
     * Get the domain that owns this alert
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get human-readable type label
     */
    public function getTypeLabel(): string
    {
        return match ($this->type) {
            'dmarc_fail' => 'DMARC Failure',
            'rbl_listed' => 'Blacklist Detection',
            'high_tti_p95' => 'High TTI (P95)',
            default => ucfirst(str_replace('_', ' ', $this->type)),
        };
    }

    /**
     * Get severity color for UI
     */
    public function getSeverityColor(): string
    {
        return match ($this->type) {
            'dmarc_fail' => 'red',
            'rbl_listed' => 'red',
            'high_tti_p95' => 'yellow',
            default => 'gray',
        };
    }
}
