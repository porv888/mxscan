<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evidence;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcRiskStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcStates;

final class DmarcStatusDeriver
{
    /**
     * @param array<string, mixed> $policy
     * @param array<string, mixed> $aggregateReporting
     */
    public function derive(
        string $protocolStatus,
        array $policy,
        array $aggregateReporting,
    ): array {
        $policyRisk = $this->policyRisk($protocolStatus, $policy);
        $reportingRisk = $this->reportingRisk($aggregateReporting);
        $state = $this->uiState($protocolStatus, $policyRisk, $reportingRisk, $policy);

        return [
            'protocol_status' => $protocolStatus,
            'risk_status' => $this->overallRisk($policyRisk, $reportingRisk),
            'policy_risk_status' => $policyRisk,
            'reporting_risk_status' => $reportingRisk,
            'state' => $state,
        ];
    }

    /**
     * @param array<string, mixed> $policy
     */
    private function policyRisk(string $protocolStatus, array $policy): string
    {
        return match ($protocolStatus) {
            DmarcProtocolStatus::NONE => DmarcRiskStatus::CRITICAL,
            DmarcProtocolStatus::PERMERROR => DmarcRiskStatus::CRITICAL,
            DmarcProtocolStatus::TEMPERROR, DmarcProtocolStatus::PARTIALLY_EVALUATED => DmarcRiskStatus::UNKNOWN,
            DmarcProtocolStatus::VALID => match ($policy['enforcement'] ?? '') {
                'reject', 'quarantine' => DmarcRiskStatus::HEALTHY,
                'partial_enforcement' => DmarcRiskStatus::WARNING,
                'monitoring' => DmarcRiskStatus::WARNING,
                default => DmarcRiskStatus::WARNING,
            },
            default => DmarcRiskStatus::UNKNOWN,
        };
    }

    /**
     * @param array<string, mixed> $aggregateReporting
     */
    private function reportingRisk(array $aggregateReporting): string
    {
        if (!($aggregateReporting['configured'] ?? false)) {
            return DmarcRiskStatus::WARNING;
        }

        foreach ($aggregateReporting['destinations'] ?? [] as $destination) {
            $status = $destination['authorization_status'] ?? '';
            if (in_array($status, ['unauthorized', 'dns_timeout', 'servfail'], true)) {
                return DmarcRiskStatus::WARNING;
            }
        }

        return DmarcRiskStatus::HEALTHY;
    }

    private function overallRisk(string $policyRisk, string $reportingRisk): string
    {
        if ($policyRisk === DmarcRiskStatus::CRITICAL) {
            return DmarcRiskStatus::CRITICAL;
        }

        if ($policyRisk === DmarcRiskStatus::UNKNOWN || $reportingRisk === DmarcRiskStatus::UNKNOWN) {
            return DmarcRiskStatus::UNKNOWN;
        }

        if ($policyRisk === DmarcRiskStatus::WARNING || $reportingRisk === DmarcRiskStatus::WARNING) {
            return DmarcRiskStatus::WARNING;
        }

        return DmarcRiskStatus::HEALTHY;
    }

    /**
     * @param array<string, mixed> $policy
     */
    private function uiState(string $protocolStatus, string $policyRisk, string $reportingRisk, array $policy): string
    {
        return match ($protocolStatus) {
            DmarcProtocolStatus::NONE => DmarcStates::MISSING,
            DmarcProtocolStatus::PERMERROR => DmarcStates::FAIL,
            DmarcProtocolStatus::TEMPERROR, DmarcProtocolStatus::PARTIALLY_EVALUATED => DmarcStates::UNKNOWN,
            DmarcProtocolStatus::VALID => match (true) {
                ($policy['enforcement'] ?? '') === 'monitoring' => DmarcStates::WARNING,
                $policyRisk === DmarcRiskStatus::HEALTHY && $reportingRisk === DmarcRiskStatus::HEALTHY => DmarcStates::PASS,
                default => DmarcStates::WARNING,
            },
            default => DmarcStates::UNKNOWN,
        };
    }
}
