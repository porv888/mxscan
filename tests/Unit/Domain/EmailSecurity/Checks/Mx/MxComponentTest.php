<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Mx;

use App\Domain\EmailSecurity\Checks\Mx\Discovery\MxRecordDiscovery;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxAddressClassifier;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxImplicitFallbackEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxNullPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordValidator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxStatusDeriver;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Checks\Mx\Recommendations\MxRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Scoring\Rules\MxScoreRule;
use Tests\Support\EmailSecurity\FakeMxDnsResolver;
use Tests\TestCase;

class MxComponentTest extends TestCase
{
    private FakeMxDnsResolver $resolver;

    protected function setUp(): void
    {
        parent::setUp();
        $this->resolver = new FakeMxDnsResolver();
    }

    public function test_valid_single_mx_target(): void
    {
        $this->resolver->setMx('example.test', [['pri' => 10, 'target' => 'mx1.example.test']]);
        $this->resolver->setA('mx1.example.test', ['8.8.8.8']);

        $native = $this->builder()->build('example.test');

        $this->assertSame(MxProtocolStatus::VALID, $native->protocolStatus);
        $this->assertSame(MxServiceMode::ACCEPTS_MAIL, $native->serviceMode);
        $this->assertSame(MxStates::PASS, $native->state);
        $this->assertSame(1, $native->usableTargets);
        $this->assertSame(15, (new MxScoreRule())->score($native)->earned);
    }

    public function test_valid_null_mx(): void
    {
        $this->resolver->setMx('example.test', [['pri' => 0, 'target' => '.']]);

        $native = $this->builder()->build('example.test');

        $this->assertTrue($native->nullMx['valid']);
        $this->assertSame(MxServiceMode::NO_INBOUND_MAIL, $native->serviceMode);
        $this->assertSame(15, (new MxScoreRule())->score($native)->earned);
        $this->assertSame([], (new MxRecommendationEvaluator())->evaluate('example.test', [
            'analysis' => (new \App\Domain\EmailSecurity\Checks\Mx\Compatibility\MxNativeAnalysisPayload())->fromNative($native),
        ]));
    }

    public function test_implicit_mx_fallback_with_ipv4(): void
    {
        $this->resolver->setMx('example.test', []);
        $this->resolver->setA('example.test', ['8.8.8.8']);

        $native = $this->builder()->build('example.test');

        $this->assertTrue($native->implicitFallback['active']);
        $this->assertSame(MxServiceMode::IMPLICIT_DELIVERY, $native->serviceMode);
        $this->assertSame(MxStates::WARNING, $native->state);
        $this->assertSame(10, (new MxScoreRule())->score($native)->earned);
    }

    public function test_no_mx_and_no_addresses_scores_zero(): void
    {
        $this->resolver->setMx('example.test', []);

        $native = $this->builder()->build('example.test');

        $this->assertSame(MxProtocolStatus::NONE, $native->protocolStatus);
        $this->assertSame(0, (new MxScoreRule())->score($native)->earned);
    }

    public function test_cname_mx_target_is_invalid(): void
    {
        $this->resolver->setMx('example.test', [['pri' => 10, 'target' => 'mx1.example.test']]);
        $this->resolver->setCname('mx1.example.test', 'mail.example.test');

        $native = $this->builder()->build('example.test');

        $this->assertSame(0, $native->usableTargets);
        $this->assertSame(MxTargetResolver::STATUS_ALIAS_INVALID, $native->targets[0]['status']);
        $this->assertSame(0, (new MxScoreRule())->score($native)->earned);
    }

    public function test_private_ip_mx_target_scores_zero(): void
    {
        $this->resolver->setMx('example.test', [['pri' => 10, 'target' => 'mx1.example.test']]);
        $this->resolver->setA('mx1.example.test', ['10.0.0.5']);

        $native = $this->builder()->build('example.test');

        $this->assertSame(MxTargetResolver::STATUS_NON_PUBLIC_ONLY, $native->targets[0]['status']);
        $this->assertSame(0, (new MxScoreRule())->score($native)->earned);
    }

    public function test_mixed_null_mx_is_permerror(): void
    {
        $this->resolver->setMx('example.test', [
            ['pri' => 0, 'target' => '.'],
            ['pri' => 10, 'target' => 'mx1.example.test'],
        ]);

        $native = $this->builder()->build('example.test');

        $this->assertSame(MxProtocolStatus::PERMERROR, $native->protocolStatus);
        $this->assertSame(0, (new MxScoreRule())->score($native)->earned);
    }

    public function test_address_classifier_public_and_private(): void
    {
        $classifier = new MxAddressClassifier();
        $this->assertTrue($classifier->classify('8.8.8.8')['usable']);
        $this->assertFalse($classifier->classify('10.0.0.1')['usable']);
        $this->assertFalse($classifier->classify('127.0.0.1')['usable']);
    }

    public function test_historical_reader_does_not_require_dns(): void
    {
        $legacy = MxAnalysisReader::fromLegacyDnsRecord(['status' => 'found'], null);
        $this->assertSame(MxStates::PASS, $legacy['state']);

        $missing = MxAnalysisReader::fromLegacyDnsRecord(['status' => 'missing'], null);
        $this->assertSame(MxStates::MISSING, $missing['state']);
    }

    private function builder(): MxEvidenceBuilder
    {
        $normalizer = new MxRecordNormalizer();

        return new MxEvidenceBuilder(
            new MxRecordDiscovery($this->resolver, $normalizer),
            $normalizer,
            new MxRecordValidator($normalizer),
            new MxNullPolicyEvaluator(),
            new MxImplicitFallbackEvaluator($this->resolver, new MxAddressClassifier()),
            new MxTargetResolver($this->resolver, new MxAddressClassifier()),
            new MxStatusDeriver(),
        );
    }
}
