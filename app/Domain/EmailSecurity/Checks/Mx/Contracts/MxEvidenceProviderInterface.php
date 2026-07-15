<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Contracts;

use App\Domain\EmailSecurity\Checks\Mx\DTO\MxEvidenceDTO;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;

interface MxEvidenceProviderInterface
{
    public function provide(CheckContextDTO $context): MxEvidenceDTO;
}
