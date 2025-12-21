<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Scan extends Model
{
    use HasFactory, HasUuids;

    protected $keyType = 'string';
    public $incrementing = false;

    protected $fillable = [
        'domain_id',
        'user_id',
        'schedule_id',
        'type',
        'status',
        'progress_pct',
        'score',
        'facts_json',
        'result_json',
        'recommendations_json',
        'recommendations_md',
        'started_at',
        'finished_at',
        'duration_ms',
    ];

    protected function casts(): array
    {
        return [
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
            'progress_pct' => 'integer',
            'score' => 'integer',
            'duration_ms' => 'integer',
            'facts_json' => 'array',
            'result_json' => 'array',
            'recommendations_json' => 'array',
        ];
    }

    /**
     * Get the domain that owns the scan.
     */
    public function domain()
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the user that owns the scan.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the schedule that triggered this scan (if any).
     */
    public function schedule()
    {
        return $this->belongsTo(Schedule::class);
    }

    /**
     * Get the scan results for the scan.
     */
    public function scanResults()
    {
        return $this->hasMany(ScanResult::class);
    }

    /**
     * Get the blacklist results for the scan.
     */
    public function blacklistResults()
    {
        return $this->hasMany(BlacklistResult::class, 'scan_id', 'id');
    }

    /**
     * Check if this is a full scan (DNS + SPF + Blacklist).
     */
    public function isFullScan(): bool
    {
        return $this->type === 'full';
    }

    /**
     * Check if this is a blacklist-only scan.
     */
    public function isBlacklistOnly(): bool
    {
        return $this->type === 'blacklist';
    }

    /**
     * Check if this scan includes DNS results.
     */
    public function hasDnsResults(): bool
    {
        return $this->isFullScan() || $this->type === 'dns';
    }

    /**
     * Check if this scan includes SPF results.
     */
    public function hasSpfResults(): bool
    {
        return $this->isFullScan() || $this->type === 'spf';
    }

    /**
     * Check if this scan includes blacklist results.
     */
    public function hasBlacklistResults(): bool
    {
        return $this->isFullScan() || $this->type === 'blacklist';
    }

    /**
     * Get a human-readable scan type label.
     */
    public function getTypeLabel(): string
    {
        return match ($this->type) {
            'full' => 'Full Scan',
            'dns' => 'DNS Only',
            'spf' => 'SPF Only',
            'blacklist' => 'Blacklist Only',
            'delivery' => 'Delivery Test',
            default => 'Unknown'
        };
    }

    /**
     * Check if this is a delivery test scan.
     */
    public function isDeliveryTest(): bool
    {
        return $this->type === 'delivery';
    }

    /**
     * Check if the scan is done (finished or failed).
     */
    public function isDone(): bool
    {
        return in_array($this->status, ['finished', 'failed']);
    }
}
