<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Builder;

class Incident extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'delivery_check_id',
        'type',
        'kind',
        'severity',
        'message',
        'meta',
        'context',
        'occurred_at',
        'resolved_at'
    ];

    protected $casts = [
        'meta' => 'array',
        'context' => 'array',
        'occurred_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    public function deliveryCheck(): BelongsTo
    {
        return $this->belongsTo(DeliveryCheck::class);
    }

    /**
     * Scope for unresolved incidents
     */
    public function scopeUnresolved(Builder $query): Builder
    {
        return $query->whereNull('resolved_at');
    }

    /**
     * Scope for resolved incidents
     */
    public function scopeResolved(Builder $query): Builder
    {
        return $query->whereNotNull('resolved_at');
    }

    /**
     * Scope by severity
     */
    public function scopeBySeverity(Builder $query, string $severity): Builder
    {
        return $query->where('severity', $severity);
    }

    /**
     * Scope for critical incidents
     */
    public function scopeCritical(Builder $query): Builder
    {
        return $query->where('severity', 'critical');
    }

    /**
     * Scope for recent incidents
     */
    public function scopeRecent(Builder $query, int $days = 7): Builder
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * Check if incident is resolved
     */
    public function isResolved(): bool
    {
        return !is_null($this->resolved_at);
    }

    /**
     * Mark incident as resolved
     */
    public function resolve(): bool
    {
        return $this->update(['resolved_at' => now()]);
    }

    /**
     * Get severity color for UI
     */
    public function getSeverityColor(): string
    {
        return match ($this->severity) {
            'incident' => 'red',
            'warning' => 'yellow',
            default => 'gray'
        };
    }

    /**
     * Get severity icon for UI
     */
    public function getSeverityIcon(): string
    {
        return match ($this->severity) {
            'incident' => 'exclamation-triangle',
            'warning' => 'exclamation-circle',
            default => 'question-mark-circle'
        };
    }

    /**
     * Get human-readable time since creation
     */
    public function getTimeAgo(): string
    {
        return $this->created_at->diffForHumans();
    }

    /**
     * Get incident priority for sorting (incident = 2, warning = 1)
     */
    public function getPriority(): int
    {
        return match ($this->severity) {
            'incident' => 2,
            'warning' => 1,
            default => 0
        };
    }

    /**
     * Scope for last N days
     */
    public function scopeLastDays(Builder $query, int $days = 7): Builder
    {
        return $query->where('occurred_at', '>=', now()->subDays($days));
    }
}
