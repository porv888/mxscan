<?php

namespace App\Services\Expiry\Contracts;

use App\Services\Expiry\DTOs\ExpiryResult;

interface DomainExpiryProvider
{
    /**
     * Detect domain expiry date.
     *
     * @param string $domain The domain name to check
     * @return ExpiryResult
     */
    public function detect(string $domain): ExpiryResult;

    /**
     * Get provider name for logging.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Check if provider is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool;
}
