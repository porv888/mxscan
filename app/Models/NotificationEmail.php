<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class NotificationEmail extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'email',
        'is_verified',
        'verification_token',
        'verified_at',
    ];

    protected $casts = [
        'is_verified' => 'boolean',
        'verified_at' => 'datetime',
    ];

    /**
     * Get the user that owns the notification email.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Generate and set a verification token.
     */
    public function generateVerificationToken(): string
    {
        $token = Str::random(64);
        $this->verification_token = $token;
        $this->save();
        
        return $token;
    }

    /**
     * Mark the email as verified.
     */
    public function markAsVerified(): void
    {
        $this->is_verified = true;
        $this->verified_at = now();
        $this->verification_token = null;
        $this->save();
    }

    /**
     * Check if the email is verified.
     */
    public function isVerified(): bool
    {
        return $this->is_verified;
    }

    /**
     * Scope to get only verified emails.
     */
    public function scopeVerified($query)
    {
        return $query->where('is_verified', true);
    }

    /**
     * Scope to get only unverified emails.
     */
    public function scopeUnverified($query)
    {
        return $query->where('is_verified', false);
    }
}
