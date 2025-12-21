<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DeliveryCheck extends Model
{
    protected $guarded = [];

    protected $casts = [
        'received_at' => 'datetime',
        'spf_pass'    => 'boolean',   // nullable boolean
        'dkim_pass'   => 'boolean',   // nullable boolean
        'dmarc_pass'  => 'boolean',   // nullable boolean
        'auth_meta'   => 'array',     // JSON
    ];

    /**
     * Get the monitor this check belongs to
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(DeliveryMonitor::class, 'delivery_monitor_id');
    }

    /**
     * Check if this is an incident
     */
    public function isIncident(): bool
    {
        return $this->verdict === 'incident';
    }

    /**
     * Check if this is a warning
     */
    public function isWarning(): bool
    {
        return $this->verdict === 'warning';
    }

    /**
     * Check if this is OK
     */
    public function isOk(): bool
    {
        return $this->verdict === 'ok';
    }

    /**
     * Get TTI in seconds
     */
    public function getTtiSeconds(): ?float
    {
        return $this->tti_ms ? round($this->tti_ms / 1000, 2) : null;
    }

    /**
     * Get formatted TTI
     */
    public function getFormattedTti(): string
    {
        if (!$this->tti_ms) {
            return 'N/A';
        }

        $seconds = $this->getTtiSeconds();
        
        if ($seconds < 60) {
            return round($seconds, 1) . 's';
        }
        
        $minutes = floor($seconds / 60);
        $remainingSeconds = $seconds % 60;
        
        if ($minutes < 60) {
            return $minutes . 'm ' . round($remainingSeconds) . 's';
        }
        
        $hours = floor($minutes / 60);
        $remainingMinutes = $minutes % 60;
        
        return $hours . 'h ' . $remainingMinutes . 'm';
    }

    /**
     * Get auth status badge color
     */
    public function getAuthBadgeColor(string $type): string
    {
        $value = $this->{$type . '_pass'};
        
        if ($value === null) {
            return 'gray';
        }
        
        return $value ? 'green' : 'red';
    }
}
