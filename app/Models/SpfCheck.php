<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SpfCheck extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'looked_up_record',
        'lookup_count',
        'warnings',
        'flattened_suggestion',
        'resolved_ips',
        'changed',
    ];

    protected function casts(): array
    {
        return [
            'warnings' => 'array',
            'resolved_ips' => 'array',
            'lookup_count' => 'integer',
            'changed' => 'boolean',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
        ];
    }

    /**
     * Get the domain that owns the SPF check.
     */
    public function domain()
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the lookup count status for UI styling.
     */
    public function getLookupStatusAttribute(): string
    {
        if ($this->lookup_count <= 7) {
            return 'safe';
        } elseif ($this->lookup_count === 8) {
            return 'warning';
        } else {
            return 'danger';
        }
    }

    /**
     * Check if the SPF record has changed compared to the previous check.
     */
    public function hasRecordChanged(): bool
    {
        return $this->changed;
    }

    /**
     * Get the previous SPF check for comparison.
     */
    public function previousCheck()
    {
        return static::where('domain_id', $this->domain_id)
            ->where('created_at', '<', $this->created_at)
            ->orderBy('created_at', 'desc')
            ->first();
    }

    /**
     * Get warning labels for display.
     */
    public function getWarningLabelsAttribute(): array
    {
        $labels = [];
        
        foreach ($this->warnings as $warning) {
            $labels[] = match($warning) {
                'PTR_USED' => 'PTR mechanism used',
                'PLUS_ALL' => '+all qualifier found',
                'INCLUDE_NXDOMAIN' => 'Include domain not found',
                'LOOP_DETECTED' => 'Circular reference detected',
                'TIMEOUT' => 'DNS timeout occurred',
                'REDIRECT_CHAIN_LONG' => 'Long redirect chain',
                'UNKNOWN_MECH' => 'Unknown mechanism',
                'LOOKUP_LIMIT' => 'DNS lookup limit exceeded',
                'NO_SPF' => 'No SPF record found',
                'MULTIPLE_SPF' => 'Multiple SPF records found',
                default => $warning
            };
        }
        
        return $labels;
    }
}
