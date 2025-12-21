<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanSnapshot extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'scan_type',
        'mx_ok',
        'spf_ok',
        'spf_lookups',
        'dmarc_ok',
        'tlsrpt_ok',
        'mtasts_ok',
        'rbl_hits',
        'score'
    ];

    protected $casts = [
        'mx_ok' => 'boolean',
        'spf_ok' => 'boolean',
        'dmarc_ok' => 'boolean',
        'tlsrpt_ok' => 'boolean',
        'mtasts_ok' => 'boolean',
        'rbl_hits' => 'array',
        'spf_lookups' => 'integer',
        'score' => 'integer',
    ];

    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    public function deltas(): HasMany
    {
        return $this->hasMany(ScanDelta::class, 'snapshot_id');
    }

    /**
     * Get the previous snapshot for comparison
     */
    public function getPreviousSnapshot(): ?ScanSnapshot
    {
        return static::where('domain_id', $this->domain_id)
            ->where('scan_type', $this->scan_type)
            ->where('id', '<', $this->id)
            ->latest('id')
            ->first();
    }

    /**
     * Check if this snapshot has any RBL hits
     */
    public function hasRblHits(): bool
    {
        return !empty($this->rbl_hits);
    }

    /**
     * Get a summary of the scan status
     */
    public function getSummary(): array
    {
        return [
            'score' => $this->score,
            'mx_ok' => $this->mx_ok,
            'spf_ok' => $this->spf_ok,
            'spf_lookups' => $this->spf_lookups,
            'dmarc_ok' => $this->dmarc_ok,
            'tlsrpt_ok' => $this->tlsrpt_ok,
            'mtasts_ok' => $this->mtasts_ok,
            'rbl_hits' => $this->rbl_hits ?? [],
            'rbl_clean' => empty($this->rbl_hits),
        ];
    }
}
