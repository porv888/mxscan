<?php

namespace App\Support;

class DomainAlign
{
    /**
     * Check if two domains are aligned according to DMARC alignment rules
     *
     * @param string $domainA First domain
     * @param string $domainB Second domain
     * @param string $mode Alignment mode: 'r' (relaxed) or 's' (strict)
     * @return bool True if domains are aligned
     */
    public static function aligned(string $domainA, string $domainB, string $mode = 'r'): bool
    {
        $domainA = strtolower(trim($domainA));
        $domainB = strtolower(trim($domainB));

        if (empty($domainA) || empty($domainB)) {
            return false;
        }

        // Strict mode: exact match only
        if ($mode === 's') {
            return $domainA === $domainB;
        }

        // Relaxed mode: exact match or organizational domain match
        if ($domainA === $domainB) {
            return true;
        }

        // Check if one is a subdomain of the other
        // For MVP: simple suffix matching
        // Later can be enhanced with Public Suffix List
        
        // Check if domainA is subdomain of domainB
        if (str_ends_with($domainA, '.' . $domainB)) {
            return true;
        }

        // Check if domainB is subdomain of domainA
        if (str_ends_with($domainB, '.' . $domainA)) {
            return true;
        }

        // Check organizational domain match (simple heuristic)
        $orgA = self::getOrganizationalDomain($domainA);
        $orgB = self::getOrganizationalDomain($domainB);

        return $orgA === $orgB;
    }

    /**
     * Extract organizational domain (simple heuristic)
     * For MVP: takes last two parts of domain
     * Later can be enhanced with Public Suffix List
     *
     * @param string $domain
     * @return string
     */
    protected static function getOrganizationalDomain(string $domain): string
    {
        $parts = explode('.', $domain);
        $count = count($parts);

        if ($count <= 2) {
            return $domain;
        }

        // Simple heuristic: take last 2 parts
        // This works for .com, .org, .net, etc.
        // Doesn't handle .co.uk, .com.au correctly (would need PSL)
        return $parts[$count - 2] . '.' . $parts[$count - 1];
    }

    /**
     * Extract domain from email address
     *
     * @param string $email
     * @return string|null
     */
    public static function extractDomain(string $email): ?string
    {
        $email = trim($email);
        
        // Handle angle brackets: "Name" <user@domain.com>
        if (preg_match('/<([^>]+)>/', $email, $matches)) {
            $email = $matches[1];
        }

        // Extract domain part
        if (preg_match('/@([a-zA-Z0-9.-]+)$/', $email, $matches)) {
            return strtolower($matches[1]);
        }

        return null;
    }
}
