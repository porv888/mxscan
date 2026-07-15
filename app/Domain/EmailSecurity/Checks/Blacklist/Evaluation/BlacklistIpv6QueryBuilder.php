<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Evaluation;

final class BlacklistIpv6QueryBuilder
{
    public function build(string $ipv6, string $zone): ?string
    {
        if (filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }

        $binary = inet_pton($ipv6);
        if ($binary === false) {
            return null;
        }

        $hex = bin2hex($binary);
        $nibbles = str_split($hex);
        $reversed = array_reverse($nibbles);

        return implode('.', $reversed) . '.' . ltrim($zone, '.');
    }
}
