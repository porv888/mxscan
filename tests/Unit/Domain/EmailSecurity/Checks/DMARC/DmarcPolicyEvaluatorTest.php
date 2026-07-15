<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use Tests\TestCase;

class DmarcPolicyEvaluatorTest extends TestCase
{
    private DmarcPolicyEvaluator $evaluator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->evaluator = new DmarcPolicyEvaluator();
    }

    public function test_testing_mode_sets_monitoring_enforcement(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=reject; t=y; rua=mailto:a@b.com');
        $policy = $this->evaluator->evaluate('example.test', $parsed, ['policy_source' => 'exact']);

        $this->assertTrue($policy['testing_mode']);
        $this->assertSame('monitoring', $policy['enforcement']);
    }

    public function test_pct_zero_is_partial_enforcement(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=reject; pct=0; rua=mailto:a@b.com');
        $policy = $this->evaluator->evaluate('example.test', $parsed, ['policy_source' => 'exact']);

        $this->assertSame(0, $policy['pct']);
        $this->assertSame('partial_enforcement', $policy['enforcement']);
    }

    public function test_subdomain_inherits_sp_policy(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@b.com');
        $policy = $this->evaluator->evaluate('mail.example.test', $parsed, [
            'policy_source' => 'organizational',
            'policy_domain' => 'example.test',
        ]);

        $this->assertSame('quarantine', $policy['effective_policy']);
        $this->assertSame('sp', $policy['inherited_from']);
    }

    public function test_subdomain_inherits_np_when_sp_missing(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=none; np=quarantine; rua=mailto:a@b.com');
        $policy = $this->evaluator->evaluate('nonexistent.example.test', $parsed, [
            'policy_source' => 'organizational',
            'policy_domain' => 'example.test',
        ]);

        $this->assertSame('quarantine', $policy['effective_policy']);
        $this->assertSame('np', $policy['inherited_from']);
    }
}
