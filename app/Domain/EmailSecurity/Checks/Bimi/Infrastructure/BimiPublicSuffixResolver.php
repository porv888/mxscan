<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Infrastructure;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiPublicSuffixInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcOrganizationalDomainResolver;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class BimiPublicSuffixResolver implements BimiPublicSuffixInterface
{
    /** @var list<string> */
    private const MULTI_PART_SUFFIXES = [
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk',
        'com.au', 'net.au', 'org.au', 'edu.au',
        'co.nz', 'org.nz', 'net.nz',
        'co.jp', 'ne.jp', 'or.jp',
        'com.br', 'net.br', 'org.br',
    ];

    public function __construct(
        private DmarcOrganizationalDomainResolver $dmarcOrgResolver,
    ) {
    }

    public function resolveOrganizationalDomain(string $authorDomain, ?DnsCollectionResultDTO $dns): array
    {
        $authorDomain = strtolower(rtrim(trim($authorDomain), '.'));

        $dmarcMeta = $this->dmarcOrgResolver->resolve($authorDomain, $dns);
        $organizational = $dmarcMeta['organizational_domain'] ?? null;
        $publicSuffix = $dmarcMeta['public_suffix_domain'] ?? null;

        if (is_string($organizational) && $organizational !== '') {
            return [
                'organizational_domain' => $organizational,
                'public_suffix_domain' => is_string($publicSuffix) ? $publicSuffix : $this->detectPublicSuffix($organizational),
            ];
        }

        return $this->fallbackResolve($authorDomain);
    }

    /**
     * @return array{organizational_domain: ?string, public_suffix_domain: ?string}
     */
    private function fallbackResolve(string $authorDomain): array
    {
        $labels = explode('.', $authorDomain);
        if (count($labels) < 2) {
            return [
                'organizational_domain' => $authorDomain,
                'public_suffix_domain' => null,
            ];
        }

        $suffix = $this->detectPublicSuffix($authorDomain);
        $suffixParts = substr_count($suffix, '.') + 1;
        $orgParts = $suffixParts + 1;

        if (count($labels) <= $orgParts) {
            return [
                'organizational_domain' => $authorDomain,
                'public_suffix_domain' => $suffix,
            ];
        }

        return [
            'organizational_domain' => implode('.', array_slice($labels, -$orgParts)),
            'public_suffix_domain' => $suffix,
        ];
    }

    private function detectPublicSuffix(string $domain): string
    {
        $domain = strtolower(rtrim(trim($domain), '.'));
        foreach (self::MULTI_PART_SUFFIXES as $suffix) {
            if ($domain === $suffix || str_ends_with($domain, '.' . $suffix)) {
                return $suffix;
            }
        }

        $labels = explode('.', $domain);

        return $labels[count($labels) - 1] ?? $domain;
    }
}
