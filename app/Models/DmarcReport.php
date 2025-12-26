<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DmarcReport extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'dmarc_ingest_id',
        'org_name',
        'org_email',
        'report_id',
        'date_range_begin',
        'date_range_end',
        'policy_domain',
        'policy_adkim',
        'policy_aspf',
        'policy_p',
        'policy_sp',
        'policy_pct',
        'total_count',
        'pass_count',
        'fail_count',
        'report_hash',
    ];

    protected function casts(): array
    {
        return [
            'date_range_begin' => 'datetime',
            'date_range_end' => 'datetime',
            'policy_pct' => 'integer',
            'total_count' => 'integer',
            'pass_count' => 'integer',
            'fail_count' => 'integer',
        ];
    }

    /**
     * Get the domain that owns this report.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the ingest record that created this report.
     */
    public function dmarcIngest(): BelongsTo
    {
        return $this->belongsTo(DmarcIngest::class);
    }

    /**
     * Get the records for this report.
     */
    public function records(): HasMany
    {
        return $this->hasMany(DmarcRecord::class);
    }

    /**
     * Calculate pass rate as percentage.
     */
    public function getPassRateAttribute(): float
    {
        if ($this->total_count === 0) {
            return 0;
        }
        return round(($this->pass_count / $this->total_count) * 100, 2);
    }

    /**
     * Generate a unique hash for deduplication.
     */
    public static function generateHash(int $domainId, string $orgName, string $reportId, int $beginTs, int $endTs): string
    {
        return hash('sha256', implode('|', [
            $domainId,
            $orgName,
            $reportId,
            $beginTs,
            $endTs,
        ]));
    }

    /**
     * Scope to filter by date range.
     */
    public function scopeInDateRange($query, $start, $end)
    {
        return $query->where('date_range_begin', '>=', $start)
                     ->where('date_range_end', '<=', $end);
    }

    /**
     * Scope to filter by organization.
     */
    public function scopeFromOrg($query, string $orgName)
    {
        return $query->where('org_name', $orgName);
    }
}
