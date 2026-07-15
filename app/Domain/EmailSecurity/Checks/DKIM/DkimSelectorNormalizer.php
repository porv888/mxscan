<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimSelectorNormalizer
{
    private const MAX_LENGTH = 63;
    private const PATTERN = '/^[a-z0-9_-]+$/';

    /**
     * @return array{selector: string, hostname: string}|null
     */
    public function normalize(string $selector, string $signingDomain): ?array
    {
        $selector = strtolower(trim($selector));
        $signingDomain = strtolower(trim($signingDomain));

        if ($selector === '' || $signingDomain === '') {
            return null;
        }

        if (strlen($selector) > self::MAX_LENGTH) {
            return null;
        }

        if (str_contains($selector, '.') || str_contains($selector, '/')
            || str_contains($selector, ' ') || str_contains($selector, '..')) {
            return null;
        }

        if (!preg_match(self::PATTERN, $selector)) {
            return null;
        }

        if (str_contains($selector, '_domainkey') || str_contains($signingDomain, '..')) {
            return null;
        }

        return [
            'selector' => $selector,
            'hostname' => "{$selector}._domainkey.{$signingDomain}",
        ];
    }
}
