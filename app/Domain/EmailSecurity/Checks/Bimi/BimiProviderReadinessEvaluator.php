<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiProviderReadinessEvaluator
{
    /**
     * @param array<string, mixed> $analysisContext
     * @return list<array<string, mixed>>
     */
    public function evaluateProfiles(array $analysisContext): array
    {
        $profiles = config('bimi.provider_profiles', []);
        $results = [];

        foreach ($profiles as $profileKey => $profile) {
            if (!is_array($profile)) {
                continue;
            }

            $results[] = $this->evaluateProfile((string) $profileKey, $profile, $analysisContext);
        }

        return $results;
    }

    /**
     * @param array<string, mixed> $profile
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function evaluateProfile(string $profileKey, array $profile, array $context): array
    {
        $requirementsMet = [];
        $requirementsMissing = [];
        $requirementsUnknown = [];

        $protocolStatus = (string) ($context['protocol_status'] ?? '');
        $indicatorStatus = (string) ($context['indicator']['status'] ?? '');
        $evidenceStatus = (string) ($context['authority_evidence']['status'] ?? '');
        $dmarcEligible = (bool) ($context['dmarc_eligibility']['core_eligible'] ?? false);

        if ($protocolStatus === BimiProtocolStatus::VALID || $protocolStatus === BimiProtocolStatus::DECLINED) {
            $requirementsMet[] = 'bimi_record';
        } else {
            $requirementsMissing[] = 'bimi_record';
        }

        if (($profile['dmarc']['core_eligible'] ?? false) === true) {
            if ($dmarcEligible) {
                $requirementsMet[] = 'dmarc';
            } else {
                $requirementsMissing[] = 'dmarc';
            }
        }

        $svgRequired = (bool) ($profile['svg']['tiny_ps_required'] ?? true);
        if ($svgRequired) {
            if ($indicatorStatus === 'valid') {
                $requirementsMet[] = 'svg';
            } elseif ($indicatorStatus === '') {
                $requirementsUnknown[] = 'svg';
            } else {
                $requirementsMissing[] = 'svg';
            }
        }

        $certificateRequired = (bool) ($profile['certificate']['required'] ?? false);
        if ($certificateRequired) {
            $allowedTypes = $profile['certificate']['types'] ?? [];
            $certType = (string) ($context['authority_evidence']['type'] ?? '');
            $certStatus = $evidenceStatus;

            if (in_array($certStatus, [BimiEvidenceStatus::VALID, BimiEvidenceStatus::PARTIALLY_VALIDATED], true)
                && (in_array($certType, $allowedTypes, true) || in_array('unknown', $allowedTypes, true))) {
                $requirementsMet[] = 'mark_certificate';
            } elseif ($certStatus === BimiEvidenceStatus::SELF_ASSERTED) {
                $requirementsMissing[] = 'mark_certificate';
            } elseif ($certStatus === BimiEvidenceStatus::UNAVAILABLE) {
                $requirementsUnknown[] = 'mark_certificate';
            } else {
                $requirementsMissing[] = 'mark_certificate';
            }
        }

        $requirementsUnknown[] = 'reputation';

        $readiness = match (true) {
            $requirementsMissing !== [] => BimiReadinessStatus::NOT_READY,
            $requirementsUnknown !== [] => BimiReadinessStatus::PARTIALLY_READY,
            $evidenceStatus === BimiEvidenceStatus::SELF_ASSERTED => BimiReadinessStatus::READY_SELF_ASSERTED,
            default => BimiReadinessStatus::READY,
        };

        return [
            'profile_key' => $profileKey,
            'label' => (string) ($profile['label'] ?? $profileKey),
            'readiness_status' => $readiness,
            'requirements_met' => $requirementsMet,
            'requirements_missing' => array_values(array_diff($requirementsMissing, $requirementsMet)),
            'requirements_unknown' => array_values(array_unique($requirementsUnknown)),
            'display' => [
                'guaranteed' => false,
            ],
        ];
    }
}
