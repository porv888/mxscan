<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DmarcRecord extends Model
{
    use HasFactory;

    protected $fillable = [
        'dmarc_report_id',
        'domain_id',
        'source_ip',
        'count',
        'disposition',
        'dkim_result',
        'dkim_domain',
        'dkim_selector',
        'dkim_aligned',
        'spf_result',
        'spf_domain',
        'spf_aligned',
        'header_from',
        'envelope_from',
        'aligned',
        'record_hash',
        'report_date',
    ];

    protected function casts(): array
    {
        return [
            'count' => 'integer',
            'dkim_aligned' => 'boolean',
            'spf_aligned' => 'boolean',
            'aligned' => 'boolean',
            'report_date' => 'date',
        ];
    }

    /**
     * Get the report this record belongs to.
     */
    public function report(): BelongsTo
    {
        return $this->belongsTo(DmarcReport::class, 'dmarc_report_id');
    }

    /**
     * Get the domain this record belongs to.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Generate a unique hash for this record.
     */
    public static function generateHash(
        string $sourceIp,
        string $headerFrom,
        ?string $disposition,
        ?string $dkimResult,
        ?string $dkimDomain,
        ?string $spfResult,
        ?string $spfDomain
    ): string {
        return hash('sha256', implode('|', [
            $sourceIp,
            $headerFrom,
            $disposition ?? '',
            $dkimResult ?? '',
            $dkimDomain ?? '',
            $spfResult ?? '',
            $spfDomain ?? '',
        ]));
    }

    /**
     * Check if DKIM passed.
     */
    public function isDkimPass(): bool
    {
        return strtolower($this->dkim_result ?? '') === 'pass';
    }

    /**
     * Check if SPF passed.
     */
    public function isSpfPass(): bool
    {
        return strtolower($this->spf_result ?? '') === 'pass';
    }

    /**
     * Scope to filter by date range.
     */
    public function scopeInDateRange($query, $start, $end)
    {
        return $query->whereBetween('report_date', [$start, $end]);
    }

    /**
     * Scope to filter aligned records only.
     */
    public function scopeAligned($query)
    {
        return $query->where('aligned', true);
    }

    /**
     * Scope to filter failing records only.
     */
    public function scopeFailing($query)
    {
        return $query->where('aligned', false);
    }

    /**
     * Scope to filter by source IP.
     */
    public function scopeFromIp($query, string $ip)
    {
        return $query->where('source_ip', $ip);
    }
}
