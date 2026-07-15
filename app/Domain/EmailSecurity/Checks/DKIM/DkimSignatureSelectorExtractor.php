<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimSignatureSelectorExtractor
{
    /**
     * Extract the s= selector from a DKIM-Signature header value.
     */
    public function extract(string $headerValue): ?string
    {
        $unfolded = preg_replace('/\r?\n[ \t]+/', '', trim($headerValue)) ?? trim($headerValue);

        if (preg_match('/(?:^|[\s;])s=([^;\s]+)/i', $unfolded, $matches)) {
            $selector = trim($matches[1]);
            return $selector !== '' ? $selector : null;
        }

        return null;
    }
}
