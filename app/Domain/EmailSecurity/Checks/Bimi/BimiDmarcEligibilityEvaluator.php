<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;

final class BimiDmarcEligibilityEvaluator
{
    /**
     * @return array<string, mixed>
     */
    public function evaluate(?DmarcNativeResult $dmarcNative, string $authorDomain, ?string $organizationalDomain): array
    {
        $minPolicy = (string) config('bimi.dmarc_core.min_policy', 'quarantine');
        $requirePct100 = (bool) config('bimi.dmarc_core.require_pct_100', true);

        $result = [
            'core_eligible' => false,
            'author_domain_eligible' => false,
            'organizational_domain_eligible' => false,
            'message_dmarc_pass_verified' => false,
            'source_analysis_version' => 'dmarc-native-v1',
            'core_requirements_met' => [],
            'core_requirements_missing' => [],
            'author_policy' => [],
            'organizational_policy' => [],
        ];

        if ($dmarcNative === null) {
            $result['core_requirements_missing'][] = 'native_dmarc_analysis_unavailable';

            return $result;
        }

        $policy = $dmarcNative->policy;
        $effectivePolicy = (string) ($policy['effective_policy'] ?? 'none');
        $pct = (int) ($policy['pct'] ?? 100);
        $protocolValid = $dmarcNative->protocolStatus === DmarcProtocolStatus::VALID;

        $orgPolicyPayload = [
            'protocol_status' => $dmarcNative->protocolStatus,
            'effective_policy' => $effectivePolicy,
            'pct' => $pct,
            'policy_domain' => $dmarcNative->policyDomain,
            'organizational_domain' => $dmarcNative->organizationalDomain,
        ];
        $result['organizational_policy'] = $orgPolicyPayload;
        $result['author_policy'] = $orgPolicyPayload;

        if (!$protocolValid) {
            $result['core_requirements_missing'][] = 'dmarc_record_valid';

            return $result;
        }

        $policyEligible = $this->policyMeetsMinimum($effectivePolicy, $minPolicy);
        $pctEligible = !$requirePct100 || $pct >= 100;

        if ($policyEligible) {
            $result['core_requirements_met'][] = 'organizational_policy_enforcement';
        } else {
            $result['core_requirements_missing'][] = 'organizational_policy_enforcement';
        }

        if ($pctEligible) {
            $result['core_requirements_met'][] = 'pct_100';
        } else {
            $result['core_requirements_missing'][] = 'pct_100';
        }

        $orgEligible = $policyEligible && $pctEligible;
        $result['organizational_domain_eligible'] = $orgEligible;

        $authorEligible = $orgEligible;
        if (is_string($organizationalDomain) && $organizationalDomain !== ''
            && strtolower($authorDomain) !== strtolower($organizationalDomain)) {
            $authorEligible = $orgEligible;
        }
        $result['author_domain_eligible'] = $authorEligible;
        $result['core_eligible'] = $orgEligible;

        return $result;
    }

    private function policyMeetsMinimum(string $effectivePolicy, string $minPolicy): bool
    {
        $rank = ['none' => 0, 'quarantine' => 1, 'reject' => 2];

        return ($rank[$effectivePolicy] ?? 0) >= ($rank[$minPolicy] ?? 1);
    }
}
