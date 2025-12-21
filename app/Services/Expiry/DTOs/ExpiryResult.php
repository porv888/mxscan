<?php

namespace App\Services\Expiry\DTOs;

use Carbon\Carbon;

class ExpiryResult
{
    public function __construct(
        public readonly ?Carbon $expiryDate,
        public readonly string $source,
        public readonly bool $success,
        public readonly ?string $error = null,
        public readonly ?float $latencyMs = null,
    ) {
    }

    public static function success(Carbon $expiryDate, string $source, float $latencyMs = null): self
    {
        return new self($expiryDate, $source, true, null, $latencyMs);
    }

    public static function failure(string $source, string $error, float $latencyMs = null): self
    {
        return new self(null, $source, false, $error, $latencyMs);
    }

    public function isValid(): bool
    {
        return $this->success && $this->expiryDate !== null && $this->expiryDate->isFuture();
    }
}
