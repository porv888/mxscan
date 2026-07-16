<?php

namespace App\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

final class DmarcScoreRule
{
    public function score(DmarcNativeResult $native): ScoreComponentDTO
    {
        $possible = (int) config('dns-scoring.dmarc.base', 30);
        $label = (string) config('dns-scoring.dmarc.label', 'DMARC');
        $policyPossible = (int) config('dns-scoring.dmarc.policy_max', 24);
        $reportingPossible = (int) config('dns-scoring.dmarc.reporting_max', 6);

        if ($native->protocolStatus === DmarcProtocolStatus::NONE
            || $native->protocolStatus === DmarcProtocolStatus::PERMERROR) {
            return $this->component($label, $possible, 0, 'missing', $native->summary, [
                $this->subcomponent('dmarc_policy', 'DMARC Policy', 0, $policyPossible, 'missing'),
                $this->subcomponent('dmarc_reports', 'DMARC Reports', 0, $reportingPossible, 'missing'),
            ]);
        }

        if ($native->protocolStatus === DmarcProtocolStatus::TEMPERROR
            || $native->protocolStatus === DmarcProtocolStatus::PARTIALLY_EVALUATED) {
            return $this->component($label, $possible, 8, 'partial', $native->summary, [
                $this->subcomponent('dmarc_policy', 'DMARC Policy', 8, $policyPossible, 'partial'),
                $this->subcomponent('dmarc_reports', 'DMARC Reports', 0, $reportingPossible, 'unknown'),
            ]);
        }

        if ($native->protocolStatus === DmarcProtocolStatus::VALID) {
            $policyEarned = min($policyPossible, $this->enforcementScore($native));
            $reportingEarned = $this->reportingComplete($native) ? $reportingPossible : 0;
            $earned = $policyEarned + $reportingEarned;
            $status = $earned === $possible ? 'ok' : ($earned === 0 ? 'missing' : 'partial');

            return $this->component($label, $possible, $earned, $status, $native->summary, [
                $this->subcomponent(
                    'dmarc_policy',
                    'DMARC Policy',
                    $policyEarned,
                    $policyPossible,
                    $policyEarned === $policyPossible ? 'ok' : 'partial',
                ),
                $this->subcomponent(
                    'dmarc_reports',
                    'DMARC Reports',
                    $reportingEarned,
                    $reportingPossible,
                    $reportingEarned === $reportingPossible ? 'ok' : 'partial',
                ),
            ]);
        }

        return $this->component($label, $possible, 0, 'partial', $native->summary, [
            $this->subcomponent('dmarc_policy', 'DMARC Policy', 0, $policyPossible, 'unknown'),
            $this->subcomponent('dmarc_reports', 'DMARC Reports', 0, $reportingPossible, 'unknown'),
        ]);
    }

    private function enforcementScore(DmarcNativeResult $native): int
    {
        $policy = $native->policy;
        $enforcement = $policy['enforcement'] ?? 'unknown';
        $effectivePolicy = $policy['effective_policy'] ?? null;
        $pct = (int) ($policy['pct'] ?? 100);
        $testingMode = (bool) ($policy['testing_mode'] ?? false);

        if ($testingMode || $effectivePolicy === 'none' || $pct === 0) {
            return 12;
        }

        return match ($enforcement) {
            'monitoring' => 12,
            'partial_enforcement' => $effectivePolicy === 'reject' ? 27 : 20,
            'quarantine' => 24,
            'reject' => 30,
            default => 0,
        };
    }

    private function component(
        string $label,
        int $possible,
        int $earned,
        string $status,
        ?string $reason,
        array $subcomponents,
    ): ScoreComponentDTO {
        return new ScoreComponentDTO(
            key: 'dmarc',
            label: $label,
            earned: $earned,
            possible: $possible,
            status: $status,
            reason: $reason,
            modelVersion: 'dmarc-v2',
            subcomponents: $subcomponents,
        );
    }

    private function reportingComplete(DmarcNativeResult $native): bool
    {
        $reporting = $native->aggregateReporting;
        if (!($reporting['configured'] ?? false) || ($reporting['destinations'] ?? []) === []) {
            return false;
        }

        foreach ($reporting['destinations'] as $destination) {
            if (!is_array($destination)) {
                return false;
            }

            if (!in_array($destination['authorization_status'] ?? 'unknown', ['authorized', 'not_required'], true)) {
                return false;
            }
        }

        $expectation = is_array($reporting['mxscan_expectation'] ?? null)
            ? $reporting['mxscan_expectation']
            : [];

        return ($expectation['expected_address'] ?? null) === null || ($expectation['present'] ?? false) === true;
    }

    private function subcomponent(string $key, string $label, int $earned, int $possible, string $status): array
    {
        return compact('key', 'label', 'earned', 'possible', 'status');
    }
}
