<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class NotificationPref extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'email_enabled',
        'slack_enabled',
        'slack_webhook',
        'weekly_reports'
    ];

    protected $casts = [
        'email_enabled' => 'boolean',
        'slack_enabled' => 'boolean',
        'weekly_reports' => 'boolean',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get or create notification preferences for a user
     */
    public static function forUser(User $user): self
    {
        return static::firstOrCreate(
            ['user_id' => $user->id],
            [
                'email_enabled' => true,
                'slack_enabled' => false,
                'weekly_reports' => true,
            ]
        );
    }

    /**
     * Check if user has any notifications enabled
     */
    public function hasNotificationsEnabled(): bool
    {
        return $this->email_enabled || $this->slack_enabled;
    }

    /**
     * Check if Slack is properly configured
     */
    public function isSlackConfigured(): bool
    {
        return $this->slack_enabled && !empty($this->slack_webhook);
    }

    /**
     * Get enabled notification channels
     */
    public function getEnabledChannels(): array
    {
        $channels = [];
        
        if ($this->email_enabled) {
            $channels[] = 'mail';
        }
        
        if ($this->isSlackConfigured()) {
            $channels[] = 'slack';
        }
        
        return $channels;
    }

    /**
     * Update Slack webhook and enable/disable based on validity
     */
    public function updateSlackWebhook(?string $webhook): bool
    {
        $this->slack_webhook = $webhook;
        $this->slack_enabled = !empty($webhook);
        
        return $this->save();
    }
}
