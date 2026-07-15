<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Scoring\Rules\DkimScoreRule;
use Tests\TestCase;

class DkimScoreRuleTest extends TestCase
{
    public function test_no_selector_available_scores_eight_points(): void
    {
        $rule = new DkimScoreRule();
        $native = new DkimNativeResult(
            state: DkimStates::UNKNOWN,
            protocolStatus: DkimProtocolStatus::PARTIALLY_EVALUATED,
            riskStatus: 'unknown',
            summary: 'No selector available',
            signingDomain: 'example.com',
            signingVerified: false,
            selectors: [],
            selectorCoverage: ['selectors_available' => false, 'selectors_tested' => 0, 'coverage_type' => 'none'],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );

        $component = $rule->score($native);

        $this->assertSame(8, $component->earned);
        $this->assertSame(20, $component->possible);
    }

    public function test_valid_rsa_2048_scores_twenty_points(): void
    {
        $rule = new DkimScoreRule();
        $native = new DkimNativeResult(
            state: DkimStates::PASS,
            protocolStatus: DkimProtocolStatus::VALID,
            riskStatus: 'healthy',
            summary: 'Valid key',
            signingDomain: 'example.com',
            signingVerified: false,
            selectors: [[
                'selector' => 'sel1',
                'source' => 'explicit',
                'record_status' => 'valid',
                'key_type' => 'rsa',
                'key_bits' => 2048,
                'testing' => false,
                'warnings' => [],
            ]],
            selectorCoverage: ['selectors_available' => true, 'selectors_tested' => 1, 'coverage_type' => 'explicit'],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );

        $this->assertSame(20, $rule->score($native)->earned);
    }

    public function test_catalog_only_miss_scores_ten_points(): void
    {
        $rule = new DkimScoreRule();
        $native = new DkimNativeResult(
            state: DkimStates::MISSING,
            protocolStatus: DkimProtocolStatus::NONE,
            riskStatus: 'critical',
            summary: 'No key for tested selectors',
            signingDomain: 'example.com',
            signingVerified: false,
            selectors: [[
                'selector' => 'google',
                'source' => 'catalog',
                'record_status' => 'none',
            ]],
            selectorCoverage: ['selectors_available' => true, 'selectors_tested' => 1, 'coverage_type' => 'catalog_only'],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );

        $this->assertSame(10, $rule->score($native)->earned);
    }
}
