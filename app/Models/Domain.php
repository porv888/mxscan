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
        'dmarc_token',
        'dmarc_last_report_at',
        'dmarc_rua_verified_at',
    ];

    // DMARC Activity state constants
    const DMARC_STATE_ACTION_REQUIRED = 'action_required';
    const DMARC_STATE_DNS_CONFIRMED_WAITING = 'dns_confirmed_waiting';
    const DMARC_STATE_ACTIVE = 'active';

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
            'dmarc_last_report_at' => 'datetime',
            'dmarc_rua_verified_at' => 'datetime',
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

    /**
     * Get the DMARC reports for the domain.
     */
    public function dmarcReports()
    {
        return $this->hasMany(DmarcReport::class);
    }

    /**
     * Get the DMARC records for the domain.
     */
    public function dmarcRecords()
    {
        return $this->hasMany(DmarcRecord::class);
    }

    /**
     * Get the DMARC daily stats for the domain.
     */
    public function dmarcDailyStats()
    {
        return $this->hasMany(DmarcDailyStat::class);
    }

    /**
     * Get the DMARC senders for the domain.
     */
    public function dmarcSenders()
    {
        return $this->hasMany(DmarcSender::class);
    }

    /**
     * Get the DMARC events for the domain.
     */
    public function dmarcEvents()
    {
        return $this->hasMany(DmarcEvent::class);
    }

    /**
     * Get the DMARC alert settings for the domain.
     */
    public function dmarcAlertSettings()
    {
        return $this->hasMany(DmarcAlertSetting::class);
    }

    /**
     * Generate or get the DMARC token for this domain.
     */
    public function getDmarcToken(): string
    {
        if (!$this->dmarc_token) {
            $this->dmarc_token = $this->generateDmarcToken();
            $this->save();
        }
        return $this->dmarc_token;
    }

    /**
     * Generate a unique DMARC token.
     */
    protected function generateDmarcToken(): string
    {
        do {
            $token = bin2hex(random_bytes(12)); // 24 char hex string
        } while (static::where('dmarc_token', $token)->exists());
        
        return $token;
    }

    /**
     * Get the full DMARC RUA email address.
     */
    public function getDmarcRuaEmailAttribute(): string
    {
        return 'dmarc+' . $this->getDmarcToken() . '@mxscan.me';
    }

    /**
     * Check if DMARC reports are being received (within last 48 hours).
     */
    public function isDmarcActive(): bool
    {
        if (!$this->dmarc_last_report_at) {
            return false;
        }
        return $this->dmarc_last_report_at->gte(now()->subHours(48));
    }

    /**
     * Check if the MXScan RUA address is configured in the domain's DMARC DNS record.
     */
    public function isDmarcRuaConfigured(): bool
    {
        $latestScan = $this->scans()->where('status', 'completed')->latest()->first();
        
        if (!$latestScan || !isset($latestScan->facts_json['dmarc'])) {
            return false;
        }
        
        $dmarcRecord = $latestScan->facts_json['dmarc'];
        if (!$dmarcRecord) {
            return false;
        }
        
        // Check if our RUA address is in the DMARC record
        return str_contains(strtolower($dmarcRecord), strtolower($this->dmarc_rua_email));
    }

    /**
     * Get the current DMARC record from DNS (from latest scan).
     */
    public function getDmarcRecordAttribute(): ?string
    {
        $latestScan = $this->scans()->where('status', 'completed')->latest()->first();
        
        if (!$latestScan || !isset($latestScan->facts_json['dmarc'])) {
            return null;
        }
        
        return $latestScan->facts_json['dmarc'];
    }

    /**
     * Get DMARC status label.
     */
    public function getDmarcStatusAttribute(): string
    {
        if (!$this->dmarc_last_report_at) {
            return 'waiting';
        }
        return $this->isDmarcActive() ? 'active' : 'inactive';
    }

    /**
     * Get the DMARC Activity state for this domain.
     * 
     * States:
     * - ACTION_REQUIRED: No DMARC record OR DMARC exists but doesn't include our RUA
     * - DNS_CONFIRMED_WAITING: DMARC record exists with our RUA, but no reports received yet
     * - ACTIVE: At least one DMARC report has been ingested
     */
    public function getDmarcActivityState(): string
    {
        // State C: ACTIVE - Reports have been received
        if ($this->dmarc_last_report_at) {
            return self::DMARC_STATE_ACTIVE;
        }

        // State B: DNS_CONFIRMED_WAITING - RUA verified but no reports yet
        if ($this->dmarc_rua_verified_at || $this->isDmarcRuaConfigured()) {
            return self::DMARC_STATE_DNS_CONFIRMED_WAITING;
        }

        // State A: ACTION_REQUIRED - Need to add/update DNS record
        return self::DMARC_STATE_ACTION_REQUIRED;
    }

    /**
     * Check if DMARC record exists in DNS (regardless of RUA).
     */
    public function hasDmarcRecord(): bool
    {
        $latestScan = $this->scans()->where('status', 'finished')->latest()->first();
        
        if (!$latestScan) {
            return false;
        }

        // Check facts_json first
        $factsJson = $latestScan->facts_json;
        if (is_array($factsJson) && !empty($factsJson['dmarc'])) {
            return true;
        }

        // Check result_json (alternative format)
        $resultJson = $latestScan->result_json;
        if (is_array($resultJson)) {
            $dmarcData = $resultJson['dns']['records']['DMARC'] ?? $resultJson['DMARC'] ?? null;
            if ($dmarcData && isset($dmarcData['status']) && $dmarcData['status'] === 'found') {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if DMARC record exists but RUA points elsewhere (not to our token).
     */
    public function hasDmarcButNotOurRua(): bool
    {
        if (!$this->hasDmarcRecord()) {
            return false;
        }
        
        return !$this->isDmarcRuaConfigured();
    }

    /**
     * Verify DMARC RUA configuration from DNS and update verification timestamp.
     * Returns true if our RUA is configured.
     */
    public function verifyAndSyncDmarcRua(): bool
    {
        $isConfigured = $this->isDmarcRuaConfigured();
        
        if ($isConfigured && !$this->dmarc_rua_verified_at) {
            // RUA is configured but we haven't recorded verification yet
            $this->update(['dmarc_rua_verified_at' => now()]);
        } elseif (!$isConfigured && $this->dmarc_rua_verified_at) {
            // RUA was removed from DNS, clear verification
            $this->update(['dmarc_rua_verified_at' => null]);
        }
        
        return $isConfigured;
    }

    /**
     * Perform a fresh DNS check for DMARC RUA configuration.
     * This bypasses cached scan results and checks DNS directly.
     */
    public function checkDmarcRuaFromDns(): bool
    {
        try {
            $dmarcRecords = dns_get_record("_dmarc.{$this->domain}", DNS_TXT);
            $dmarcRecord = !empty($dmarcRecords) ? $dmarcRecords[0]['txt'] ?? null : null;
            
            if (!$dmarcRecord) {
                // No DMARC record found
                if ($this->dmarc_rua_verified_at) {
                    $this->update(['dmarc_rua_verified_at' => null]);
                }
                return false;
            }
            
            // Check if our RUA address is in the DMARC record
            $isConfigured = str_contains(strtolower($dmarcRecord), strtolower($this->dmarc_rua_email));
            
            if ($isConfigured && !$this->dmarc_rua_verified_at) {
                $this->update(['dmarc_rua_verified_at' => now()]);
            } elseif (!$isConfigured && $this->dmarc_rua_verified_at) {
                $this->update(['dmarc_rua_verified_at' => null]);
            }
            
            return $isConfigured;
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::warning('DMARC DNS check failed', [
                'domain' => $this->domain,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Get DMARC Activity state label for display.
     */
    public function getDmarcActivityStateLabelAttribute(): string
    {
        return match ($this->getDmarcActivityState()) {
            self::DMARC_STATE_ACTION_REQUIRED => 'Needs DNS Record',
            self::DMARC_STATE_DNS_CONFIRMED_WAITING => 'Waiting for Reports',
            self::DMARC_STATE_ACTIVE => 'Active',
            default => 'Unknown',
        };
    }

    /**
     * Get DMARC Activity state badge color for display.
     */
    public function getDmarcActivityStateBadgeColorAttribute(): string
    {
        return match ($this->getDmarcActivityState()) {
            self::DMARC_STATE_ACTION_REQUIRED => 'amber',
            self::DMARC_STATE_DNS_CONFIRMED_WAITING => 'blue',
            self::DMARC_STATE_ACTIVE => 'green',
            default => 'gray',
        };
    }

    /**
     * Get the unified DMARC setup status using DmarcStatusService.
     * This is the single source of truth for DMARC status across all pages.
     * 
     * @param int $staleThresholdDays Days after which reports are considered stale
     * @return array
     */
    public function getDmarcSetupStatus(int $staleThresholdDays = 7): array
    {
        return app(\App\Services\Dmarc\DmarcStatusService::class)->getStatus($this, $staleThresholdDays);
    }

    /**
     * Check if DMARC record has any RUA address (regardless of destination).
     */
    public function hasDmarcRua(): bool
    {
        $dmarcRecord = $this->dmarc_record;
        if (!$dmarcRecord) {
            return false;
        }
        
        return (bool) preg_match('/rua\s*=\s*mailto:/i', $dmarcRecord);
    }
}
