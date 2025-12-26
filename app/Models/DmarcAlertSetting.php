<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DmarcAlertSetting extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'user_id',
        'new_sender_enabled',
        'fail_spike_enabled',
        'alignment_drop_enabled',
        'dkim_fail_spike_enabled',
        'spf_fail_spike_enabled',
        'spike_threshold_pct',
        'min_volume_threshold',
        'new_sender_days',
        'throttle_hours',
        'last_new_sender_alert',
        'last_fail_spike_alert',
        'last_alignment_drop_alert',
        'last_dkim_fail_spike_alert',
        'last_spf_fail_spike_alert',
    ];

    protected function casts(): array
    {
        return [
            'new_sender_enabled' => 'boolean',
            'fail_spike_enabled' => 'boolean',
            'alignment_drop_enabled' => 'boolean',
            'dkim_fail_spike_enabled' => 'boolean',
            'spf_fail_spike_enabled' => 'boolean',
            'spike_threshold_pct' => 'integer',
            'min_volume_threshold' => 'integer',
            'new_sender_days' => 'integer',
            'throttle_hours' => 'integer',
            'last_new_sender_alert' => 'datetime',
            'last_fail_spike_alert' => 'datetime',
            'last_alignment_drop_alert' => 'datetime',
            'last_dkim_fail_spike_alert' => 'datetime',
            'last_spf_fail_spike_alert' => 'datetime',
        ];
    }

    /**
     * Get the domain this setting belongs to.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the user this setting belongs to.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Check if a specific alert type can be sent (not throttled).
     */
    public function canSendAlert(string $type): bool
    {
        $lastAlertField = "last_{$type}_alert";
        
        if (!isset($this->$lastAlertField)) {
            return true;
        }

        $lastAlert = $this->$lastAlertField;
        if (!$lastAlert) {
            return true;
        }

        return $lastAlert->addHours($this->throttle_hours)->isPast();
    }

    /**
     * Record that an alert was sent.
     */
    public function recordAlertSent(string $type): void
    {
        $lastAlertField = "last_{$type}_alert";
        $this->update([$lastAlertField => now()]);
    }

    /**
     * Check if new sender alerts are enabled and not throttled.
     */
    public function shouldAlertNewSender(): bool
    {
        return $this->new_sender_enabled && $this->canSendAlert('new_sender');
    }

    /**
     * Check if fail spike alerts are enabled and not throttled.
     */
    public function shouldAlertFailSpike(): bool
    {
        return $this->fail_spike_enabled && $this->canSendAlert('fail_spike');
    }

    /**
     * Check if alignment drop alerts are enabled and not throttled.
     */
    public function shouldAlertAlignmentDrop(): bool
    {
        return $this->alignment_drop_enabled && $this->canSendAlert('alignment_drop');
    }

    /**
     * Check if DKIM fail spike alerts are enabled and not throttled.
     */
    public function shouldAlertDkimFailSpike(): bool
    {
        return $this->dkim_fail_spike_enabled && $this->canSendAlert('dkim_fail_spike');
    }

    /**
     * Check if SPF fail spike alerts are enabled and not throttled.
     */
    public function shouldAlertSpfFailSpike(): bool
    {
        return $this->spf_fail_spike_enabled && $this->canSendAlert('spf_fail_spike');
    }

    /**
     * Get or create settings for a domain and user.
     */
    public static function getOrCreate(int $domainId, int $userId): self
    {
        return static::firstOrCreate(
            ['domain_id' => $domainId, 'user_id' => $userId],
            [
                'new_sender_enabled' => true,
                'fail_spike_enabled' => true,
                'alignment_drop_enabled' => true,
                'dkim_fail_spike_enabled' => true,
                'spf_fail_spike_enabled' => true,
                'spike_threshold_pct' => 15,
                'min_volume_threshold' => 100,
                'new_sender_days' => 7,
                'throttle_hours' => 6,
            ]
        );
    }
}
