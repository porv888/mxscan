<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Carbon\Carbon;

class Schedule extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'user_id',
        'scan_type',
        'frequency',
        'cron_expression',
        'next_run_at',
        'last_run_at',
        'is_running',
        'last_run_status',
        'status',
        'settings',
    ];

    protected $casts = [
        'next_run_at' => 'datetime',
        'last_run_at' => 'datetime',
        'is_running' => 'boolean',
        'settings' => 'array',
    ];

    /**
     * Get the domain that owns this schedule.
     */
    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    /**
     * Get the user that owns this schedule.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get all scans triggered by this schedule.
     */
    public function scans()
    {
        return $this->hasMany(Scan::class);
    }

    /**
     * Get the latest scan triggered by this schedule.
     */
    public function latestScan()
    {
        return $this->hasOne(Scan::class)->latestOfMany();
    }

    /**
     * Get the scan type display name.
     */
    public function getScanTypeDisplayAttribute(): string
    {
        return match ($this->scan_type) {
            'dns_security' => 'DNS Security',
            'blacklist' => 'Blacklist Only',
            'both' => 'DNS + Blacklist',
            default => ucfirst($this->scan_type),
        };
    }

    /**
     * Get the frequency display name.
     */
    public function getFrequencyDisplayAttribute(): string
    {
        return match ($this->frequency) {
            'daily' => 'Daily',
            'weekly' => 'Weekly',
            'monthly' => 'Monthly',
            'custom' => 'Custom (' . $this->cron_expression . ')',
            default => ucfirst($this->frequency),
        };
    }

    /**
     * Get the status badge class.
     */
    public function getStatusBadgeClassAttribute(): string
    {
        return match ($this->status) {
            'active' => 'bg-green-100 text-green-800',
            'paused' => 'bg-yellow-100 text-yellow-800',
            'disabled' => 'bg-red-100 text-red-800',
            default => 'bg-gray-100 text-gray-800',
        };
    }

    /**
     * Get the status icon.
     */
    public function getStatusIconAttribute(): string
    {
        return match ($this->status) {
            'active' => 'play-circle',
            'paused' => 'pause-circle',
            'disabled' => 'stop-circle',
            default => 'help-circle',
        };
    }

    /**
     * Calculate the next run time based on frequency.
     * Ensures next_run is always in the future: max(now, last_run + freq)
     */
    public function calculateNextRun(): Carbon
    {
        $now = Carbon::now();
        $baseTime = $this->last_run_at ? $this->last_run_at->copy() : $now->copy();
        
        $nextRun = match ($this->frequency) {
            'daily' => $baseTime->addDay()->setTime(2, 0), // 2 AM daily
            'weekly' => $baseTime->addWeek()->startOfWeek()->addDay()->setTime(2, 0), // Monday 2 AM
            'monthly' => $baseTime->addMonth()->startOfMonth()->setTime(2, 0), // 1st of month 2 AM
            'custom' => $this->calculateCustomNextRun($baseTime),
            default => $baseTime->addWeek(),
        };
        
        // Ensure next run is always in the future
        return $nextRun->max($now);
    }

    /**
     * Calculate next run for custom cron expression.
     */
    private function calculateCustomNextRun(?Carbon $from = null): Carbon
    {
        $from = $from ?: Carbon::now();
        
        if (!$this->cron_expression) {
            return $from->copy()->addWeek();
        }

        try {
            $cron = new \Cron\CronExpression($this->cron_expression);
            return Carbon::instance($cron->getNextRunDate($from));
        } catch (\Exception $e) {
            \Log::warning("Invalid cron expression for schedule {$this->id}: {$this->cron_expression}");
            return $from->copy()->addWeek();
        }
    }

    /**
     * Check if the schedule is due to run.
     */
    public function isDue(): bool
    {
        return $this->status === 'active' 
            && $this->next_run_at 
            && $this->next_run_at->isPast();
    }

    /**
     * Mark the schedule as completed and calculate next run.
     */
    public function markCompleted(): void
    {
        $this->update([
            'last_run_at' => now(),
            'next_run_at' => $this->calculateNextRun(),
        ]);
    }

    /**
     * Pause the schedule.
     */
    public function pause(): void
    {
        $this->update(['status' => 'paused']);
    }

    /**
     * Resume the schedule.
     */
    public function resume(): void
    {
        $this->update([
            'status' => 'active',
            'next_run_at' => $this->calculateNextRun(),
        ]);
    }

    /**
     * Compute next run from a specific time.
     */
    public function computeNextRun(?Carbon $from = null): ?Carbon
    {
        $from = $from ?: now();
        
        if ($this->frequency === 'custom' && $this->cron_expression) {
            try {
                $cron = new \Cron\CronExpression($this->cron_expression);
                return Carbon::instance($cron->getNextRunDate($from));
            } catch (\Exception $e) {
                \Log::warning("Invalid cron expression for schedule {$this->id}: {$this->cron_expression}");
                return $from->copy()->addWeek();
            }
        }
        
        return match ($this->frequency) {
            'daily' => $from->copy()->addDay()->setTime(2, 0),
            'weekly' => $from->copy()->addWeek()->startOfWeek()->addDay()->setTime(2, 0),
            'monthly' => $from->copy()->addMonth()->startOfMonth()->setTime(2, 0),
            default => $from->copy()->addWeek(),
        };
    }

    /**
     * Get the last run status badge class.
     */
    public function getLastRunStatusBadgeClassAttribute(): string
    {
        return match ($this->last_run_status) {
            'ok' => 'bg-green-100 text-green-800',
            'warning' => 'bg-yellow-100 text-yellow-800',
            'failed' => 'bg-red-100 text-red-800',
            default => 'bg-gray-100 text-gray-800',
        };
    }
}