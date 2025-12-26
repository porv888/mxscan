<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DmarcEvent extends Model
{
    use HasFactory;

    const TYPE_NEW_SENDER = 'new_sender';
    const TYPE_FAIL_SPIKE = 'fail_spike';
    const TYPE_ALIGNMENT_DROP = 'alignment_drop';
    const TYPE_DKIM_FAIL_SPIKE = 'dkim_fail_spike';
    const TYPE_SPF_FAIL_SPIKE = 'spf_fail_spike';
    const TYPE_POLICY_CHANGE = 'policy_change';

    const SEVERITY_INFO = 'info';
    const SEVERITY_WARNING = 'warning';
    const SEVERITY_CRITICAL = 'critical';

    protected $fillable = [
        'domain_id',
        'type',
        'severity',
        'title',
        'description',
        'meta',
        'dmarc_sender_id',
        'source_ip',
        'previous_rate',
        'current_rate',
        'volume',
        'event_date',
        'notified',
        'notified_at',
        'acknowledged',
        'acknowledged_at',
        'acknowledged_by',
    ];

    protected function casts(): array
    {
        return [
            'meta' => 'array',
            'previous_rate' => 'float',
            'current_rate' => 'float',
            'volume' => 'integer',
            'event_date' => 'date',
            'notified' => 'boolean',
            'notified_at' => 'datetime',
            'acknowledged' => 'boolean',
            'acknowledged_at' => 'datetime',
        ];
    }

    /**
     * Get the domain this event belongs to.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the sender related to this event.
     */
    public function sender(): BelongsTo
    {
        return $this->belongsTo(DmarcSender::class, 'dmarc_sender_id');
    }

    /**
     * Get the user who acknowledged this event.
     */
    public function acknowledgedByUser(): BelongsTo
    {
        return $this->belongsTo(User::class, 'acknowledged_by');
    }

    /**
     * Mark event as notified.
     */
    public function markNotified(): void
    {
        $this->update([
            'notified' => true,
            'notified_at' => now(),
        ]);
    }

    /**
     * Mark event as acknowledged.
     */
    public function acknowledge(int $userId): void
    {
        $this->update([
            'acknowledged' => true,
            'acknowledged_at' => now(),
            'acknowledged_by' => $userId,
        ]);
    }

    /**
     * Get human-readable type label.
     */
    public function getTypeLabelAttribute(): string
    {
        return match ($this->type) {
            self::TYPE_NEW_SENDER => 'New Sender Detected',
            self::TYPE_FAIL_SPIKE => 'Fail Spike',
            self::TYPE_ALIGNMENT_DROP => 'Alignment Drop',
            self::TYPE_DKIM_FAIL_SPIKE => 'DKIM Fail Spike',
            self::TYPE_SPF_FAIL_SPIKE => 'SPF Fail Spike',
            self::TYPE_POLICY_CHANGE => 'Policy Change',
            default => ucfirst(str_replace('_', ' ', $this->type)),
        };
    }

    /**
     * Get severity color for UI.
     */
    public function getSeverityColorAttribute(): string
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 'red',
            self::SEVERITY_WARNING => 'amber',
            self::SEVERITY_INFO => 'blue',
            default => 'gray',
        };
    }

    /**
     * Get severity icon for UI.
     */
    public function getSeverityIconAttribute(): string
    {
        return match ($this->severity) {
            self::SEVERITY_CRITICAL => 'alert-triangle',
            self::SEVERITY_WARNING => 'alert-circle',
            self::SEVERITY_INFO => 'info',
            default => 'bell',
        };
    }

    /**
     * Scope to filter unnotified events.
     */
    public function scopeUnnotified($query)
    {
        return $query->where('notified', false);
    }

    /**
     * Scope to filter unacknowledged events.
     */
    public function scopeUnacknowledged($query)
    {
        return $query->where('acknowledged', false);
    }

    /**
     * Scope to filter by type.
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope to filter recent events.
     */
    public function scopeRecent($query, int $days = 7)
    {
        return $query->where('event_date', '>=', now()->subDays($days)->toDateString());
    }

    /**
     * Create a new sender event.
     */
    public static function createNewSenderEvent(Domain $domain, DmarcSender $sender, int $volume): self
    {
        return static::create([
            'domain_id' => $domain->id,
            'type' => self::TYPE_NEW_SENDER,
            'severity' => self::SEVERITY_WARNING,
            'title' => 'New sender detected: ' . $sender->source_ip,
            'description' => "A new sender ({$sender->source_ip}) has started sending email as {$domain->domain}. This could be a legitimate new service or a potential spoofing attempt.",
            'meta' => [
                'source_ip' => $sender->source_ip,
                'ptr_record' => $sender->ptr_record,
                'volume' => $volume,
            ],
            'dmarc_sender_id' => $sender->id,
            'source_ip' => $sender->source_ip,
            'volume' => $volume,
            'event_date' => now()->toDateString(),
        ]);
    }

    /**
     * Create a fail spike event.
     */
    public static function createFailSpikeEvent(
        Domain $domain,
        string $type,
        float $previousRate,
        float $currentRate,
        int $volume,
        ?DmarcSender $topSender = null
    ): self {
        $severity = ($currentRate - $previousRate) >= 25 ? self::SEVERITY_CRITICAL : self::SEVERITY_WARNING;
        
        $typeLabel = match ($type) {
            self::TYPE_DKIM_FAIL_SPIKE => 'DKIM',
            self::TYPE_SPF_FAIL_SPIKE => 'SPF',
            default => 'Alignment',
        };

        return static::create([
            'domain_id' => $domain->id,
            'type' => $type,
            'severity' => $severity,
            'title' => "{$typeLabel} fail rate increased by " . round($currentRate - $previousRate, 1) . '%',
            'description' => "The {$typeLabel} fail rate for {$domain->domain} increased from " . round($previousRate, 1) . "% to " . round($currentRate, 1) . "%. This may indicate a configuration issue or unauthorized sending.",
            'meta' => [
                'previous_rate' => $previousRate,
                'current_rate' => $currentRate,
                'volume' => $volume,
                'top_sender' => $topSender?->source_ip,
            ],
            'dmarc_sender_id' => $topSender?->id,
            'source_ip' => $topSender?->source_ip,
            'previous_rate' => $previousRate,
            'current_rate' => $currentRate,
            'volume' => $volume,
            'event_date' => now()->toDateString(),
        ]);
    }
}
