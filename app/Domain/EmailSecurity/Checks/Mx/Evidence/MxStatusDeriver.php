<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evidence;

use App\Domain\EmailSecurity\Checks\Mx\Discovery\MxDiscoveryResult;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;

final class MxStatusDeriver
{
    /**
     * @param list<array<string, mixed>> $targets
     * @param array<string, mixed> $nullMx
     * @param array<string, mixed> $implicitFallback
     * @param list<array{code: string, message: string}> $errors
     */
    public function derive(
        MxDiscoveryResult $discovery,
        array $nullMx,
        array $implicitFallback,
        array $targets,
        array $errors,
    ): array {
        if ($discovery->query->outcome === \App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsQueryResult::OUTCOME_NXDOMAIN) {
            return $this->status(
                MxProtocolStatus::NONE,
                MxRiskStatus::CRITICAL,
                MxStates::FAIL,
                MxServiceMode::UNKNOWN,
                'The scanned domain does not exist in DNS.',
            );
        }

        if ($discovery->hasDnsFailure()) {
            return $this->status(
                MxProtocolStatus::TEMPERROR,
                MxRiskStatus::UNKNOWN,
                MxStates::UNKNOWN,
                MxServiceMode::UNKNOWN,
                'MX records could not be evaluated reliably because of a temporary DNS failure.',
            );
        }

        if (($nullMx['valid'] ?? false) === true) {
            return $this->status(
                MxProtocolStatus::VALID,
                MxRiskStatus::HEALTHY,
                MxStates::PASS,
                MxServiceMode::NO_INBOUND_MAIL,
                'This domain explicitly declares that it does not accept inbound email.',
            );
        }

        if (($nullMx['mixed'] ?? false) === true || ($errors !== [] && $targets === [])) {
            return $this->status(
                MxProtocolStatus::PERMERROR,
                MxRiskStatus::CRITICAL,
                MxStates::FAIL,
                MxServiceMode::UNKNOWN,
                'The published MX configuration is invalid or ambiguous.',
            );
        }

        if ($discovery->isMissing()) {
            if (($implicitFallback['active'] ?? false) === true) {
                return $this->status(
                    MxProtocolStatus::VALID,
                    MxRiskStatus::WARNING,
                    MxStates::WARNING,
                    MxServiceMode::IMPLICIT_DELIVERY,
                    'No MX records are published, but the domain resolves to usable addresses via SMTP implicit-MX fallback.',
                );
            }

            if (($implicitFallback['dns_failure'] ?? false) === true) {
                return $this->status(
                    MxProtocolStatus::TEMPERROR,
                    MxRiskStatus::UNKNOWN,
                    MxStates::UNKNOWN,
                    MxServiceMode::UNKNOWN,
                    'MX records could not be evaluated reliably because of a temporary DNS failure.',
                );
            }

            return $this->status(
                MxProtocolStatus::NONE,
                MxRiskStatus::CRITICAL,
                MxStates::MISSING,
                MxServiceMode::UNKNOWN,
                'No MX records or usable implicit delivery route were found for this domain.',
            );
        }

        $usableTargets = array_values(array_filter(
            $targets,
            fn (array $target) => in_array($target['status'] ?? '', [
                MxTargetResolver::STATUS_USABLE,
                MxTargetResolver::STATUS_USABLE_WITH_WARNINGS,
                MxTargetResolver::STATUS_PARTIALLY_RESOLVED,
            ], true),
        ));

        if ($usableTargets === []) {
            return $this->status(
                MxProtocolStatus::PERMERROR,
                MxRiskStatus::CRITICAL,
                MxStates::FAIL,
                MxServiceMode::ACCEPTS_MAIL,
                'Explicit MX records exist, but no usable inbound delivery target was found.',
            );
        }

        $defectiveTargets = array_values(array_filter(
            $targets,
            fn (array $target) => !in_array($target['status'] ?? '', [
                MxTargetResolver::STATUS_USABLE,
            ], true),
        ));

        if ($defectiveTargets !== []) {
            return $this->status(
                MxProtocolStatus::PARTIALLY_EVALUATED,
                MxRiskStatus::WARNING,
                MxStates::WARNING,
                MxServiceMode::ACCEPTS_MAIL,
                'Valid inbound mail exchangers are published, but the MX record set contains operational defects.',
            );
        }

        return $this->status(
            MxProtocolStatus::VALID,
            MxRiskStatus::HEALTHY,
            MxStates::PASS,
            MxServiceMode::ACCEPTS_MAIL,
            'Valid inbound mail exchangers are published.',
        );
    }

    /**
     * @return array{protocol_status: string, risk_status: string, state: string, service_mode: string, summary: string}
     */
    private function status(
        string $protocolStatus,
        string $riskStatus,
        string $state,
        string $serviceMode,
        string $summary,
    ): array {
        return [
            'protocol_status' => $protocolStatus,
            'risk_status' => $riskStatus,
            'state' => $state,
            'service_mode' => $serviceMode,
            'summary' => $summary,
        ];
    }
}
