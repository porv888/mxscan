<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DmarcDailyStat extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'date',
        'total_count',
        'aligned_count',
        'dkim_pass_count',
        'spf_pass_count',
        'disposition_none',
        'disposition_quarantine',
        'disposition_reject',
        'alignment_rate',
        'dkim_pass_rate',
        'spf_pass_rate',
        'unique_sources',
        'new_sources',
        'report_count',
    ];

    protected function casts(): array
    {
        return [
            'date' => 'date',
            'total_count' => 'integer',
            'aligned_count' => 'integer',
            'dkim_pass_count' => 'integer',
            'spf_pass_count' => 'integer',
            'disposition_none' => 'integer',
            'disposition_quarantine' => 'integer',
            'disposition_reject' => 'integer',
            'alignment_rate' => 'float',
            'dkim_pass_rate' => 'float',
            'spf_pass_rate' => 'float',
            'unique_sources' => 'integer',
            'new_sources' => 'integer',
            'report_count' => 'integer',
        ];
    }

    /**
     * Get the domain this stat belongs to.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Calculate and update rates from counts.
     */
    public function calculateRates(): void
    {
        if ($this->total_count > 0) {
            $this->alignment_rate = round(($this->aligned_count / $this->total_count) * 100, 2);
            $this->dkim_pass_rate = round(($this->dkim_pass_count / $this->total_count) * 100, 2);
            $this->spf_pass_rate = round(($this->spf_pass_count / $this->total_count) * 100, 2);
        } else {
            $this->alignment_rate = 0;
            $this->dkim_pass_rate = 0;
            $this->spf_pass_rate = 0;
        }
    }

    /**
     * Get fail rate (inverse of alignment rate).
     */
    public function getFailRateAttribute(): float
    {
        return 100 - $this->alignment_rate;
    }

    /**
     * Scope to filter by date range.
     */
    public function scopeInDateRange($query, $start, $end)
    {
        return $query->whereBetween('date', [$start, $end]);
    }

    /**
     * Scope to get stats for the last N days.
     */
    public function scopeLastDays($query, int $days)
    {
        return $query->where('date', '>=', now()->subDays($days)->toDateString());
    }

    /**
     * Get or create a stat record for a domain and date.
     */
    public static function getOrCreate(int $domainId, string $date): self
    {
        return static::firstOrCreate(
            ['domain_id' => $domainId, 'date' => $date],
            [
                'total_count' => 0,
                'aligned_count' => 0,
                'dkim_pass_count' => 0,
                'spf_pass_count' => 0,
                'disposition_none' => 0,
                'disposition_quarantine' => 0,
                'disposition_reject' => 0,
                'alignment_rate' => 0,
                'dkim_pass_rate' => 0,
                'spf_pass_rate' => 0,
                'unique_sources' => 0,
                'new_sources' => 0,
                'report_count' => 0,
            ]
        );
    }
}
