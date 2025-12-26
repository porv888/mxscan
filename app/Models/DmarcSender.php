<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DmarcSender extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'source_ip',
        'header_from',
        'org_name',
        'ptr_record',
        'asn',
        'asn_org',
        'total_count',
        'aligned_count',
        'dkim_pass_count',
        'spf_pass_count',
        'disposition_none',
        'disposition_quarantine',
        'disposition_reject',
        'dkim_domain',
        'dkim_selector',
        'spf_domain',
        'first_seen_at',
        'last_seen_at',
        'is_new',
        'is_risky',
    ];

    protected function casts(): array
    {
        return [
            'total_count' => 'integer',
            'aligned_count' => 'integer',
            'dkim_pass_count' => 'integer',
            'spf_pass_count' => 'integer',
            'disposition_none' => 'integer',
            'disposition_quarantine' => 'integer',
            'disposition_reject' => 'integer',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'is_new' => 'boolean',
            'is_risky' => 'boolean',
        ];
    }

    /**
     * Get the domain this sender belongs to.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get events related to this sender.
     */
    public function events(): HasMany
    {
        return $this->hasMany(DmarcEvent::class);
    }

    /**
     * Calculate alignment pass rate.
     */
    public function getAlignmentRateAttribute(): float
    {
        if ($this->total_count === 0) {
            return 0;
        }
        return round(($this->aligned_count / $this->total_count) * 100, 2);
    }

    /**
     * Calculate DKIM pass rate.
     */
    public function getDkimPassRateAttribute(): float
    {
        if ($this->total_count === 0) {
            return 0;
        }
        return round(($this->dkim_pass_count / $this->total_count) * 100, 2);
    }

    /**
     * Calculate SPF pass rate.
     */
    public function getSpfPassRateAttribute(): float
    {
        if ($this->total_count === 0) {
            return 0;
        }
        return round(($this->spf_pass_count / $this->total_count) * 100, 2);
    }

    /**
     * Calculate fail rate.
     */
    public function getFailRateAttribute(): float
    {
        return 100 - $this->alignment_rate;
    }

    /**
     * Check if sender is considered new (first seen within N days).
     */
    public function isNewSender(int $days = 7): bool
    {
        if (!$this->first_seen_at) {
            return true;
        }
        return $this->first_seen_at->gte(now()->subDays($days));
    }

    /**
     * Check if sender is risky (high fail rate).
     */
    public function isRiskySender(float $threshold = 20): bool
    {
        return $this->fail_rate >= $threshold && $this->total_count >= 10;
    }

    /**
     * Update the is_new and is_risky flags.
     */
    public function updateFlags(int $newDays = 7, float $riskThreshold = 20): void
    {
        $this->is_new = $this->isNewSender($newDays);
        $this->is_risky = $this->isRiskySender($riskThreshold);
        $this->save();
    }

    /**
     * Get suggested fix based on failure type.
     */
    public function getSuggestedFixAttribute(): ?string
    {
        if ($this->alignment_rate >= 95) {
            return null;
        }

        if ($this->dkim_pass_rate < 50) {
            return 'Check DKIM signing configuration for this sender. Ensure the sending service is properly configured to sign emails with your domain\'s DKIM key.';
        }

        if ($this->spf_pass_rate < 50) {
            return 'Add this sender\'s IP or include mechanism to your SPF record. The IP ' . $this->source_ip . ' should be authorized to send on behalf of your domain.';
        }

        if ($this->dkim_pass_rate >= 80 && $this->spf_pass_rate >= 80 && $this->alignment_rate < 80) {
            return 'Authentication is passing but alignment is failing. Consider using a subdomain strategy or ensure the From header domain matches your SPF/DKIM domain.';
        }

        return 'Review the authentication configuration for this sender to improve deliverability.';
    }

    /**
     * Scope to filter new senders.
     */
    public function scopeNew($query)
    {
        return $query->where('is_new', true);
    }

    /**
     * Scope to filter risky senders.
     */
    public function scopeRisky($query)
    {
        return $query->where('is_risky', true);
    }

    /**
     * Scope to filter by last seen within N days.
     */
    public function scopeActiveWithin($query, int $days)
    {
        return $query->where('last_seen_at', '>=', now()->subDays($days));
    }

    /**
     * Get or create a sender record.
     */
    public static function getOrCreate(int $domainId, string $sourceIp): self
    {
        return static::firstOrCreate(
            ['domain_id' => $domainId, 'source_ip' => $sourceIp],
            [
                'total_count' => 0,
                'aligned_count' => 0,
                'dkim_pass_count' => 0,
                'spf_pass_count' => 0,
                'disposition_none' => 0,
                'disposition_quarantine' => 0,
                'disposition_reject' => 0,
                'first_seen_at' => now(),
                'last_seen_at' => now(),
                'is_new' => true,
                'is_risky' => false,
            ]
        );
    }
}
