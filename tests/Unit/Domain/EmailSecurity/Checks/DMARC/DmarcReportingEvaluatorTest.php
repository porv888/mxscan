<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcReportingEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use Tests\TestCase;

class DmarcReportingEvaluatorTest extends TestCase
{
    private DmarcReportingEvaluator $evaluator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->evaluator = new DmarcReportingEvaluator();
    }

    public function test_multiple_rua_destinations(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=quarantine; rua=mailto:a@b.com,mailto:c@d.com');
        $aggregate = $this->evaluator->evaluateAggregate($parsed);

        $this->assertTrue($aggregate['configured']);
        $this->assertCount(2, $aggregate['destinations']);
    }

    public function test_malformed_rua_is_not_configured(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=quarantine; rua=not-a-uri');
        $aggregate = $this->evaluator->evaluateAggregate($parsed);

        $this->assertFalse($aggregate['configured']);
        $this->assertSame([], $aggregate['destinations']);
    }

    public function test_ruf_configured(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=quarantine; ruf=mailto:f@b.com');
        $failure = $this->evaluator->evaluateFailure($parsed);

        $this->assertTrue($failure['configured']);
        $this->assertCount(1, $failure['destinations']);
    }
}
