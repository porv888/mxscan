<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Evaluation;

final class BlacklistIpv4QueryBuilder
{
    public function build(string $ipv4, string $zone): ?string
    {
        if (filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }

        $parts = explode('.', $ipv4);
        if (count($parts) !== 4) {
            return null;
        }

        return implode('.', array_reverse($parts)) . '.' . ltrim($zone, '.');
    }
}
