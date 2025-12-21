<?php

namespace App\Support;

class SubaddressToken
{
    /**
     * Generate a secure token for a monitor ID
     */
    public static function make(int $id, string $secret): string
    {
        $hmac = substr(hash_hmac('sha256', (string)$id, $secret), 0, 20);
        $plain = $id . '.' . $hmac;
        return rtrim(strtr(base64_encode($plain), '+/', '-_'), '=');
    }

    /**
     * Parse and validate a token, returning the monitor ID if valid
     */
    public static function parse(string $token, string $secret): ?int
    {
        $plain = base64_decode(strtr($token, '-_', '+/'), true);
        if ($plain === false || !str_contains($plain, '.')) {
            return null;
        }
        
        [$id, $hmac] = explode('.', $plain, 2);
        if (!ctype_digit($id)) {
            return null;
        }
        
        $expect = substr(hash_hmac('sha256', $id, $secret), 0, 20);
        return hash_equals($expect, $hmac) ? (int)$id : null;
    }
}
