<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Contracts;

use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

interface BimiPublicSuffixInterface
{
    /**
     * @return array{organizational_domain: ?string, public_suffix_domain: ?string}
     */
    public function resolveOrganizationalDomain(string $authorDomain, ?DnsCollectionResultDTO $dns): array;
}
