<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Domain extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'domain',
        'environment',
        'provider_guess',
        'score_last',
        'last_scanned_at',
        'status',
        'spf_lookup_count',
        'domain_expires_at',
        'domain_expiry_source',
        'domain_expiry_detected_at',
        'ssl_expires_at',
        'ssl_expiry_source',
        'ssl_expiry_detected_at',
    ];

    protected function casts(): array
    {
        return [
            'last_scanned_at' => 'datetime',
            'score_last' => 'integer',
            'spf_lookup_count' => 'integer',
            'domain_expires_at' => 'datetime',
            'domain_expiry_detected_at' => 'datetime',
            'ssl_expires_at' => 'datetime',
            'ssl_expiry_detected_at' => 'datetime',
        ];
    }

    /**
     * Get the user that owns the domain.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the scans for the domain.
     */
    public function scans()
    {
        return $this->hasMany(Scan::class);
    }

    /**
     * Get the schedules for the domain.
     */
    public function schedules()
    {
        return $this->hasMany(Schedule::class);
    }

    /**
     * Get the active schedule for the domain.
     */
    public function activeSchedule()
    {
        return $this->hasOne(Schedule::class)->where('status', 'active');
    }

    /**
     * Get the latest blacklist results for this domain.
     */
    public function latestBlacklistResults()
    {
        return $this->hasManyThrough(
            BlacklistResult::class,
            Scan::class,
            'domain_id',
            'scan_id',
            'id',
            'id'
        )->whereHas('scan', function ($query) {
            $query->latest()->limit(1);
        });
    }

    /**
     * Get blacklist status for this domain.
     */
    public function getBlacklistStatusAttribute()
    {
        $latestScan = $this->scans()
            ->whereHas('blacklistResults')
            ->latest()
            ->first();

        if (!$latestScan) {
            return 'not-checked';
        }

        $blacklistResults = $latestScan->blacklistResults;
        $listedCount = $blacklistResults->where('status', 'listed')->count();

        return $listedCount > 0 ? 'listed' : 'clean';
    }

    /**
     * Get blacklist count for this domain.
     */
    public function getBlacklistCountAttribute()
    {
        $latestScan = $this->scans()
            ->whereHas('blacklistResults')
            ->latest()
            ->first();

        if (!$latestScan) {
            return 0;
        }

        return $latestScan->blacklistResults->where('status', 'listed')->count();
    }

    /**
     * Get the SPF checks for the domain.
     */
    public function spfChecks()
    {
        return $this->hasMany(SpfCheck::class);
    }

    /**
     * Get the latest SPF check for the domain.
     */
    public function latestSpfCheck()
    {
        return $this->hasOne(SpfCheck::class)->latest('created_at');
    }

    /**
     * Get the SPF lookup count status for UI styling.
     */
    public function getSpfLookupStatusAttribute(): string
    {
        if ($this->spf_lookup_count <= 7) {
            return 'safe';
        } elseif ($this->spf_lookup_count === 8) {
            return 'warning';
        } else {
            return 'danger';
        }
    }

    /**
     * Check if SPF lookup count is approaching the limit.
     */
    public function isSpfLookupCountHigh(): bool
    {
        return $this->spf_lookup_count >= 9;
    }

    /**
     * Update the cached SPF lookup count.
     */
    public function updateSpfLookupCount(int $count): void
    {
        $this->update(['spf_lookup_count' => $count]);
    }

    /**
     * Get the scan snapshots for the domain.
     */
    public function scanSnapshots()
    {
        return $this->hasMany(ScanSnapshot::class);
    }

    /**
     * Get the latest scan snapshot for the domain.
     */
    public function latestScanSnapshot()
    {
        return $this->hasOne(ScanSnapshot::class)->latest('created_at');
    }

    /**
     * Get the scan deltas for the domain.
     */
    public function scanDeltas()
    {
        return $this->hasMany(ScanDelta::class);
    }

    /**
     * Get the incidents for the domain.
     */
    public function incidents()
    {
        return $this->hasMany(Incident::class);
    }

    /**
     * Get unresolved incidents for the domain.
     */
    public function unresolvedIncidents()
    {
        return $this->hasMany(Incident::class)->unresolved();
    }

    /**
     * Get recent incidents for the domain.
     */
    public function recentIncidents(int $days = 7)
    {
        return $this->hasMany(Incident::class)->recent($days);
    }

    /**
     * Get the delivery monitors for the domain.
     */
    public function deliveryMonitors()
    {
        return $this->hasMany(DeliveryMonitor::class);
    }

    /**
     * Check if domain registration is expiring soon.
     */
    public function isDomainExpiringSoon(int $days = 30): bool
    {
        if (!$this->domain_expires_at) {
            return false;
        }

        return $this->domain_expires_at->lte(now()->addDays($days));
    }

    /**
     * Check if SSL certificate is expiring soon.
     */
    public function isSslExpiringSoon(int $days = 30): bool
    {
        if (!$this->ssl_expires_at) {
            return false;
        }

        return $this->ssl_expires_at->lte(now()->addDays($days));
    }

    /**
     * Get days until domain expiry.
     */
    public function getDaysUntilDomainExpiry(): ?int
    {
        if (!$this->domain_expires_at) {
            return null;
        }

        return now()->diffInDays($this->domain_expires_at, false);
    }

    /**
     * Get days until SSL expiry.
     */
    public function getDaysUntilSslExpiry(): ?int
    {
        if (!$this->ssl_expires_at) {
            return null;
        }

        return now()->diffInDays($this->ssl_expires_at, false);
    }

    /**
     * Get expiry badge color based on days remaining.
     */
    public function getExpiryBadgeColor(?int $days): string
    {
        if ($days === null) {
            return 'gray';
        }

        if ($days < 0) {
            return 'red'; // Expired
        }

        if ($days <= 7) {
            return 'red'; // Critical
        }

        if ($days <= 30) {
            return 'amber'; // Warning
        }

        return 'green'; // Safe
    }
}
