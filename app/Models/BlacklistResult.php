<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class BlacklistResult extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'provider',
        'ip_address',
        'status',
        'message',
        'removal_url',
    ];

    protected $casts = [
        'status' => 'string',
    ];

    /**
     * Get the scan that owns this blacklist result.
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class, 'scan_id', 'id');
    }

    /**
     * Check if this IP is listed on the RBL.
     */
    public function isListed(): bool
    {
        return $this->status === 'listed';
    }

    /**
     * Get the status with appropriate styling class.
     */
    public function getStatusBadgeClass(): string
    {
        return match ($this->status) {
            'listed' => 'bg-red-100 text-red-800',
            'ok' => 'bg-green-100 text-green-800',
            default => 'bg-gray-100 text-gray-800',
        };
    }

    /**
     * Get the status icon.
     */
    public function getStatusIcon(): string
    {
        return match ($this->status) {
            'listed' => '❌',
            'ok' => '✅',
            default => '❓',
        };
    }
}