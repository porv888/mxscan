<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluationResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use App\Domain\EmailSecurity\Checks\SPF\Evidence\SpfStatusDeriver;
use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAssessment;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;
use Tests\TestCase;

class SpfStatusDeriverTest extends TestCase
{
    private SpfStatusDeriver $deriver;

    protected function setUp(): void
    {
        parent::setUp();
        $this->deriver = new SpfStatusDeriver();
    }

    public function test_exactly_ten_lookups_is_valid_warning(): void
    {
        $derived = $this->deriver->derive(
            $this->discovery(),
            new SpfValidationResult(terms: []),
            new SpfEvaluationResult(),
            $this->counter(10),
        );

        $this->assertSame(SpfProtocolStatus::VALID, $derived->protocolStatus);
        $this->assertSame(SpfRiskStatus::WARNING, $derived->riskStatus);
        $this->assertSame(SpfStates::WARNING, $derived->state);
    }

    public function test_eleven_lookup_attempt_is_permerror(): void
    {
        $counter = $this->counter(10);
        $counter->increment('include', 'overflow.test', 'TXT');

        $derived = $this->deriver->derive(
            $this->discovery(),
            new SpfValidationResult(terms: []),
            new SpfEvaluationResult(lookupLimitExceeded: true),
            $counter,
        );

        $this->assertSame(SpfProtocolStatus::PERMERROR, $derived->protocolStatus);
        $this->assertSame(SpfRiskStatus::CRITICAL, $derived->riskStatus);
        $this->assertSame(SpfStates::FAIL, $derived->state);
    }

    public function test_dns_timeout_is_temperror(): void
    {
        $derived = $this->deriver->derive(
            new SpfDiscoveryResult(domain: 'example.test', source: 'dns_query', dnsFailure: true, dnsError: 'timeout'),
            new SpfValidationResult(terms: []),
            new SpfEvaluationResult(),
            new SpfLookupCounter(),
        );

        $this->assertSame(SpfProtocolStatus::TEMPERROR, $derived->protocolStatus);
        $this->assertSame(SpfStates::UNKNOWN, $derived->state);
    }

    public function test_unsupported_macro_is_partially_evaluated(): void
    {
        $derived = $this->deriver->derive(
            $this->discovery(),
            new SpfValidationResult(terms: [], warnings: [['code' => 'UNSUPPORTED_SPF_MACRO', 'message' => 'x']]),
            new SpfEvaluationResult(),
            new SpfLookupCounter(),
            new SpfMacroAssessment(hasUnsupportedMacro: true, unsupportedTokens: ['%{i}']),
        );

        $this->assertSame(SpfProtocolStatus::PARTIALLY_EVALUATED, $derived->protocolStatus);
        $this->assertSame(SpfStates::WARNING, $derived->state);
    }

    private function discovery(): SpfDiscoveryResult
    {
        return new SpfDiscoveryResult(
            domain: 'example.test',
            source: 'dns_collection',
            record: 'v=spf1 -all',
        );
    }

    private function counter(int $count): SpfLookupCounter
    {
        $counter = new SpfLookupCounter();
        for ($i = 0; $i < $count; $i++) {
            $counter->increment('include', "inc{$i}.test", 'TXT');
        }

        return $counter;
    }
}
