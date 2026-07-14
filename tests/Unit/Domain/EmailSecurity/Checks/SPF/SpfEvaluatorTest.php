<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;
use App\Services\Dns\DnsResult;
use Tests\Support\EmailSecurity\FakeDnsClient;
use Tests\TestCase;

class SpfEvaluatorTest extends TestCase
{
    public function test_redirect_is_ignored_when_all_exists(): void
    {
        $dns = new FakeDnsClient();
        $dns->setTxt('redirect.test', new DnsResult(['v=spf1 -all'], true));

        $evaluator = new SpfEvaluator(new SpfDnsDependencyResolver($dns), new SpfParser());
        $terms = (new SpfParser())->parse('v=spf1 redirect=redirect.test -all', 'example.test');
        $validation = new SpfValidationResult(terms: $terms, hasTerminalAll: true);

        $result = $evaluator->evaluate($terms, 'example.test', $validation);

        $this->assertSame(0, $evaluator->lookupCounter()->count());
        $this->assertFalse($result->hasTemperror);
    }

    public function test_include_without_spf_record_is_permerror(): void
    {
        $dns = new FakeDnsClient();
        $dns->setTxt('missing.test', new DnsResult([], true));

        $evaluator = new SpfEvaluator(new SpfDnsDependencyResolver($dns), new SpfParser());
        $terms = (new SpfParser())->parse('v=spf1 include:missing.test -all', 'example.test');
        $validation = new SpfValidationResult(terms: $terms, hasTerminalAll: true);

        $result = $evaluator->evaluate($terms, 'example.test', $validation);

        $this->assertTrue(collect($result->errors)->contains(fn ($e) => ($e['code'] ?? '') === 'INCLUDE_NONE_PERMERROR'));
    }

    public function test_dns_timeout_is_temperror_not_void(): void
    {
        $dns = new FakeDnsClient();
        $dns->setTxt('timeout.test', new DnsResult([], false, 'DNS timeout'));

        $evaluator = new SpfEvaluator(new SpfDnsDependencyResolver($dns), new SpfParser());
        $terms = (new SpfParser())->parse('v=spf1 exists:timeout.test -all', 'example.test');
        $validation = new SpfValidationResult(terms: $terms, hasTerminalAll: true);

        $result = $evaluator->evaluate($terms, 'example.test', $validation);

        $this->assertTrue($result->hasTemperror);
        $this->assertSame(0, $evaluator->lookupCounter()->voidCount());
    }
}
