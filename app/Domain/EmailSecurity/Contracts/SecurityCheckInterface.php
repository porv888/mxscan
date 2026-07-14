<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

interface SecurityCheckInterface
{
    public function key(): string;

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO;
}
