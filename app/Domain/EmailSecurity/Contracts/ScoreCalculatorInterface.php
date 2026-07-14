<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\ScoreResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;

interface ScoreCalculatorInterface
{
    public function calculate(ScoringInputDTO $input): ScoreResultDTO;
}
