<?php

namespace Tests\Unit\Domain\EmailSecurity\Scoring\Rules;

use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\Scoring\Rules\SpfScoreRule;
use Tests\Support\EmailSecurity\SpfNativeResultFactory;
use Tests\TestCase;

class SpfScoreRuleTest extends TestCase
{
    private SpfScoreRule $rule;

    protected function setUp(): void
    {
        parent::setUp();
        $this->rule = new SpfScoreRule();
    }

    public function test_no_spf_policy_scores_zero(): void
    {
        $native = SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::NONE,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::MISSING,
            summary: 'SPF record missing.',
            rawRecord: null,
            terminalPolicy: SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            parsedTerminalPolicy: null,
        );

        $component = $this->rule->score($native);

        $this->assertSame(0, $component->earned);
        $this->assertSame(20, $component->possible);
        $this->assertSame('missing', $component->status);
        $this->assertSame('spf-v2', $component->modelVersion);
    }

    public function test_valid_hard_fail_three_lookups_scores_twenty(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(lookupCount: 3));

        $this->assertSame(20, $component->earned);
        $this->assertSame('ok', $component->status);
    }

    public function test_valid_hard_fail_eight_lookups_scores_eighteen(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            lookupCount: 8,
            riskStatus: SpfRiskStatus::WARNING,
            state: SpfStates::WARNING,
            summary: 'SPF configuration valid; elevated lookup count (8/10).',
        ));

        $this->assertSame(18, $component->earned);
        $this->assertSame('partial', $component->status);
    }

    public function test_valid_hard_fail_ten_lookups_scores_sixteen(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            lookupCount: 10,
            riskStatus: SpfRiskStatus::WARNING,
            state: SpfStates::WARNING,
            summary: 'SPF configuration valid; lookup budget at limit (10/10).',
        ));

        $this->assertSame(16, $component->earned);
        $this->assertSame('partial', $component->status);
    }

    public function test_valid_soft_fail_scores_fifteen(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            rawRecord: 'v=spf1 ~all',
            terminalPolicy: SpfTerminalPolicy::SOFT_FAIL,
            parsedTerminalPolicy: ['qualifier' => '~', 'mechanism' => 'all', 'position' => 1],
            lookupCount: 2,
        ));

        $this->assertSame(15, $component->earned);
    }

    public function test_valid_neutral_scores_ten(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            rawRecord: 'v=spf1 ?all',
            terminalPolicy: SpfTerminalPolicy::NEUTRAL,
            parsedTerminalPolicy: ['qualifier' => '?', 'mechanism' => 'all', 'position' => 1],
            lookupCount: 2,
        ));

        $this->assertSame(10, $component->earned);
    }

    public function test_no_terminal_policy_scores_ten(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            rawRecord: 'v=spf1 include:example.com',
            terminalPolicy: SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            parsedTerminalPolicy: null,
            lookupCount: 1,
        ));

        $this->assertSame(10, $component->earned);
    }

    public function test_deprecated_ptr_deducts_two_points(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            warnings: [['code' => 'DEPRECATED_PTR', 'message' => 'The ptr mechanism is deprecated.']],
        ));

        $this->assertSame(18, $component->earned);
    }

    public function test_unsupported_macro_scores_eight(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PARTIALLY_EVALUATED,
            riskStatus: SpfRiskStatus::UNKNOWN,
            state: SpfStates::UNKNOWN,
            summary: 'SPF configuration could not be fully evaluated.',
        ));

        $this->assertSame(8, $component->earned);
        $this->assertSame('partial', $component->status);
    }

    public function test_timeout_scores_eight(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::TEMPERROR,
            riskStatus: SpfRiskStatus::UNKNOWN,
            state: SpfStates::UNKNOWN,
            summary: 'SPF configuration could not be fully evaluated.',
        ));

        $this->assertSame(8, $component->earned);
    }

    public function test_plus_all_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF policy uses a weak terminal qualifier.',
            rawRecord: 'v=spf1 +all',
            terminalPolicy: SpfTerminalPolicy::PASS_ALL,
            parsedTerminalPolicy: ['qualifier' => '+', 'mechanism' => 'all', 'position' => 1],
            errors: [['code' => 'PLUS_ALL', 'message' => 'SPF uses +all which allows any sender.']],
        ));

        $this->assertSame(0, $component->earned);
    }

    public function test_multiple_records_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF configuration invalid (multiple records).',
            multipleRecords: true,
        ));

        $this->assertSame(0, $component->earned);
    }

    public function test_invalid_syntax_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF configuration invalid.',
            errors: [['code' => 'INVALID_VERSION', 'message' => 'Invalid SPF version.']],
        ));

        $this->assertSame(0, $component->earned);
    }

    public function test_eleven_lookups_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF lookup budget exceeded.',
            lookupCount: 11,
            errors: [['code' => 'LOOKUP_LIMIT', 'message' => 'SPF lookup budget exceeded.']],
        ));

        $this->assertSame(0, $component->earned);
    }

    public function test_third_void_lookup_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF configuration invalid.',
            errors: [['code' => 'VOID_LOOKUP_LIMIT', 'message' => 'SPF void lookup limit exceeded.']],
        ));

        $this->assertSame(0, $component->earned);
    }

    public function test_include_permerror_scores_zero(): void
    {
        $component = $this->rule->score(SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF configuration invalid.',
            errors: [['code' => 'INCLUDE_NONE_PERMERROR', 'message' => 'Include returned none.']],
        ));

        $this->assertSame(0, $component->earned);
    }
}
