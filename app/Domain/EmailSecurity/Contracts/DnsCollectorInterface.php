<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

interface DnsCollectorInterface
{
    public function collect(string $domain): DnsCollectionResultDTO;
}
