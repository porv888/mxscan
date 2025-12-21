<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScanResult extends Model
{
    use HasFactory;

    protected $fillable = [
        'scan_id',
        'phase',
        'status',
        'message',
        'raw_data',
    ];

    protected function casts(): array
    {
        return [
            'raw_data' => 'array',
        ];
    }

    /**
     * Get the scan that owns the scan result.
     */
    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }
}
