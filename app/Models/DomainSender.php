<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DomainSender extends Model
{
    use HasFactory;

    public const SOURCE_DETECTED = 'detected';
    public const SOURCE_USER_ADDED = 'user_added';

    public const CONFIDENCE_CONFIRMED = 'confirmed';
    public const CONFIDENCE_LIKELY = 'likely';
    public const CONFIDENCE_UNKNOWN = 'unknown';

    public const STATUS_CONFIRMED = 'confirmed';
    public const STATUS_REJECTED = 'rejected';
    public const STATUS_PENDING = 'pending';

    protected $fillable = [
        'domain_id',
        'sender_type',
        'provider',
        'mechanism',
        'value',
        'source',
        'confidence',
        'confirmation_status',
        'confirmed_by',
        'confirmed_at',
        'last_seen_at',
        'is_active',
        'fingerprint',
    ];

    protected function casts(): array
    {
        return [
            'confirmed_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'is_active' => 'boolean',
        ];
    }

    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    public function confirmer(): BelongsTo
    {
        return $this->belongsTo(User::class, 'confirmed_by');
    }

    public static function fingerprint(
        string $senderType,
        ?string $provider,
        string $mechanism,
        string $value,
    ): string {
        return hash('sha256', implode('|', [
            strtolower(trim($senderType)),
            strtolower(trim((string) $provider)),
            strtolower(trim($mechanism)),
            strtolower(trim($value)),
        ]));
    }
}
