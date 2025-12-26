<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Cashier\Billable;
use Illuminate\Support\Facades\Log;

class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, Billable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
        'status',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * Get the domains for the user.
     */
    public function domains()
    {
        return $this->hasMany(Domain::class);
    }

    /**
     * Get the scans for the user.
     */
    public function scans()
    {
        return $this->hasMany(Scan::class);
    }

    /**
     * Get the user's subscriptions.
     */
    public function subscriptions()
    {
        return $this->hasMany(Subscription::class);
    }

    /**
     * Get the user's invoices.
     */
    public function invoices()
    {
        return $this->hasMany(Invoice::class);
    }

    /**
     * Check if user is admin or superadmin.
     */
    public function isAdmin()
    {
        return in_array($this->role, ['admin', 'superadmin']);
    }

    /**
     * Check if user is superadmin.
     */
    public function isSuperAdmin()
    {
        return $this->role === 'superadmin';
    }

    /**
     * Get the user's current active subscription (helper method).
     */
    public function currentSubscription()
    {
        // Prefer the most recent active subscription by started_at, and ensure not canceled
        $sub = $this->subscriptions()
            ->where('status', 'active')
            ->whereNull('canceled_at')
            ->where(function($q){
                $q->whereNull('renews_at')
                  ->orWhere('renews_at', '>', now());
            })
            ->orderByDesc('updated_at')
            ->orderByDesc('started_at')
            ->orderByDesc('id')
            ->first();

        // Debug trace to diagnose mismatches between Admin and Profile/Billing
        try {
            Log::debug('currentSubscription selection', [
                'user_id' => $this->id,
                'subscription_id' => $sub?->id,
                'status' => $sub?->status,
                'plan_id' => $sub?->plan_id,
                'started_at' => optional($sub?->started_at)?->toDateTimeString(),
                'renews_at' => optional($sub?->renews_at)?->toDateTimeString(),
                'canceled_at' => optional($sub?->canceled_at)?->toDateTimeString(),
            ]);
        } catch (\Throwable $e) {
            // no-op
        }

        return $sub;
    }

    /**
     * Get the user's current plan model (or null).
     */
    public function currentPlan()
    {
        return optional($this->currentSubscription())->plan;
    }

    /**
     * Get the domain limit for the user's current plan.
     */
    public function domainLimit(): int
    {
        $plan = $this->currentPlan();
        if ($plan && !is_null($plan->domain_limit)) {
            return (int) $plan->domain_limit;
        }
        // fallback to config-driven limits based on tier
        return (int) (config('plans.limits.' . $this->currentTier()) ?? 1);
    }

    /**
     * Resolve the current plan key: freemium | premium | ultra
     */
    public function currentPlanKey(): string
    {
        $names = config('plans.names');
        $plan = $this->currentPlan();
        if (!$plan) {
            return 'freemium';
        }
        $name = trim(strtolower($plan->name));
        // Compare against configured names to be robust to label changes
        if ($name === trim(strtolower($names['ultra'] ?? 'Ultra'))) {
            return 'ultra';
        }
        if ($name === trim(strtolower($names['premium'] ?? 'Premium'))) {
            return 'premium';
        }
        return 'freemium';
    }

    /**
     * Current tier derived from internal subscription/plan data.
     */
    public function currentTier(): string
    {
        return $this->currentPlanKey();
    }

    /**
     * Get the number of domains used by the user.
     */
    public function domainsUsed(): int
    {
        return $this->domains()->count();
    }

    /**
     * Get the notification preferences for the user.
     */
    public function notificationPrefs()
    {
        return $this->hasOne(NotificationPref::class);
    }

    /**
     * Get or create notification preferences for the user.
     */
    public function getNotificationPrefs(): NotificationPref
    {
        return NotificationPref::forUser($this);
    }

    /**
     * Check if user can use monitoring features (plan-gated).
     */
    public function canUseMonitoring(): bool
    {
        $planKey = $this->currentPlanKey();
        return in_array($planKey, ['premium', 'ultra']);
    }

    /**
     * Check if user can use weekly reports (plan-gated).
     */
    public function canUseWeeklyReports(): bool
    {
        return $this->canUseMonitoring();
    }

    /**
     * Check if user can use Slack notifications (plan-gated).
     */
    public function canUseSlackNotifications(): bool
    {
        return $this->canUseMonitoring();
    }

    /**
     * Check if user can use blacklist scanning (plan-gated).
     */
    public function canUseBlacklist(): bool
    {
        $planKey = $this->currentPlanKey();
        return in_array($planKey, ['premium', 'ultra']);
    }

    /**
     * Get the monitor limit for the user's current plan.
     */
    public function monitorLimit(): int
    {
        $plan = $this->currentPlan();
        $planKey = $this->currentPlanKey();
        
        // Check if plan has explicit monitor_limit field (future enhancement)
        if ($plan && isset($plan->monitor_limit)) {
            return (int) $plan->monitor_limit;
        }
        
        // Fallback to config-based limits
        return match($planKey) {
            'premium' => (int) config('monitoring.limits.premium', 10),
            'ultra'   => (int) config('monitoring.limits.ultra', 50),
            default   => (int) config('monitoring.limits.freemium', 1),
        };
    }

    /**
     * Get the number of monitors used by the user.
     */
    public function monitorsUsed(): int
    {
        return $this->deliveryMonitors()->count();
    }

    /**
     * Get the delivery monitors for the user.
     */
    public function deliveryMonitors()
    {
        return $this->hasMany(DeliveryMonitor::class);
    }

    /**
     * Get the notification emails for the user.
     */
    public function notificationEmails()
    {
        return $this->hasMany(NotificationEmail::class);
    }

    /**
     * Get all verified notification emails for the user.
     */
    public function verifiedNotificationEmails()
    {
        return $this->notificationEmails()->verified();
    }

    /**
     * Route notifications for the mail channel.
     * Returns array of emails: primary email + all verified notification emails.
     */
    public function routeNotificationForMail($notification)
    {
        $emails = [$this->email];
        
        // Add all verified notification emails
        $additionalEmails = $this->verifiedNotificationEmails()
            ->pluck('email')
            ->toArray();
        
        if (!empty($additionalEmails)) {
            $emails = array_merge($emails, $additionalEmails);
        }
        
        // Return array of unique emails
        return array_unique($emails);
    }

    /**
     * Check if user can use DMARC visibility features.
     * Free users get limited access, paid users get full access.
     */
    public function canUseDmarcFull(): bool
    {
        return $this->canUseMonitoring();
    }

    /**
     * Get the DMARC history limit in days based on plan.
     */
    public function dmarcHistoryDays(): int
    {
        return $this->canUseDmarcFull() ? 90 : 7;
    }

    /**
     * Get the DMARC sender limit based on plan.
     */
    public function dmarcSenderLimit(): int
    {
        return $this->canUseDmarcFull() ? 100 : 5;
    }
}
