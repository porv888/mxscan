<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class MxScoreRule
{
    public function score(MxNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.mx.max', 15);
        $label = (string) config('dns-scoring.mx.label', 'MX Records');

        if ($native->protocolStatus === MxProtocolStatus::TEMPERROR
            || $native->evaluationCompleteness === 'incomplete') {
            return $this->component($label, $possible, 5, 'partial', $native->summary);
        }

        if (($native->nullMx['valid'] ?? false) === true) {
            return $this->component($label, $possible, 15, 'ok', $native->summary);
        }

        if ($this->scoresZero($native)) {
            return $this->component($label, $possible, 0, 'missing', $native->summary);
        }

        if ($native->serviceMode === MxServiceMode::IMPLICIT_DELIVERY) {
            return $this->component($label, $possible, 10, 'partial', $native->summary);
        }

        if ($native->usableTargets > 0 && $native->invalidTargets > 0) {
            return $this->component($label, $possible, 12, 'partial', $native->summary);
        }

        if ($native->protocolStatus === MxProtocolStatus::PARTIALLY_EVALUATED) {
            return $this->component($label, $possible, 12, 'partial', $native->summary);
        }

        return $this->component($label, $possible, 15, 'ok', $native->summary);
    }

    private function scoresZero(MxNativeResult $native): bool
    {
        if ($native->protocolStatus === MxProtocolStatus::NONE) {
            return true;
        }

        if ($native->protocolStatus === MxProtocolStatus::PERMERROR) {
            return true;
        }

        if ($native->usableTargets === 0 && $native->serviceMode !== MxServiceMode::IMPLICIT_DELIVERY) {
            return true;
        }

        $allAlias = $native->targets !== [] && count(array_filter(
            $native->targets,
            fn (array $target) => ($target['status'] ?? '') === MxTargetResolver::STATUS_ALIAS_INVALID,
        )) === count($native->targets);

        return $allAlias;
    }

    private function component(string $label, int $possible, int $earned, string $status, ?string $reason): ScoreComponentDTO
    {
        return new ScoreComponentDTO(
            key: 'mx',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'mx-v1',
        );
    }
}
