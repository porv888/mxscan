<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\MtaSts;

use App\Domain\EmailSecurity\Checks\MtaSts\Matching\MtaStsMxMatcher;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsRiskStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsDnsRecordParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsPolicyParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsTxtReconstructor;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidator;
use App\Domain\EmailSecurity\Scoring\Rules\MtaStsScoreRule;
use Tests\TestCase;

class MtaStsComponentTest extends TestCase
{
    public function test_exact_mx_match(): void
    {
        $matcher = new MtaStsMxMatcher(new MtaStsPolicyValidator());
        $results = $matcher->match([
            ['hostname' => 'mx1.mail.example.com', 'priority' => 10, 'normalized_hostname' => 'mx1.mail.example.com'],
        ], ['mx1.mail.example.com']);

        $this->assertTrue($results[0]->matchesPolicy);
    }

    public function test_wildcard_mx_match(): void
    {
        $matcher = new MtaStsMxMatcher(new MtaStsPolicyValidator());
        $results = $matcher->match([
            ['hostname' => 'mx1.mail.example.com', 'priority' => 10, 'normalized_hostname' => 'mx1.mail.example.com'],
        ], ['*.mail.example.com']);

        $this->assertTrue($results[0]->matchesPolicy);
    }

    public function test_wildcard_does_not_match_bare_apex(): void
    {
        $matcher = new MtaStsMxMatcher(new MtaStsPolicyValidator());
        $results = $matcher->match([
            ['hostname' => 'example.com', 'priority' => 10, 'normalized_hostname' => 'example.com'],
        ], ['*.example.com']);

        $this->assertFalse($results[0]->matchesPolicy);
    }

    public function test_unsafe_suffix_rejected(): void
    {
        $matcher = new MtaStsMxMatcher(new MtaStsPolicyValidator());
        $results = $matcher->match([
            ['hostname' => 'evil-example.com', 'priority' => 10, 'normalized_hostname' => 'evil-example.com'],
        ], ['*.example.com']);

        $this->assertFalse($results[0]->matchesPolicy);
    }

    public function test_selects_case_sensitive_version_token(): void
    {
        $records = [
            'v=STSv1; id=20260714;',
            'v=stsv1; id=bad;',
            'not-mta-sts',
        ];

        $selected = MtaStsTxtReconstructor::selectIndicatorRecords($records);
        $this->assertSame(['v=STSv1; id=20260714;'], $selected);
    }

    public function test_joins_multi_string_txt_within_one_rr(): void
    {
        $joined = MtaStsTxtReconstructor::fromDnsRow([
            'txt' => ['v=STSv1;', ' id=20260714;'],
        ]);

        $this->assertSame('v=STSv1; id=20260714;', $joined);
    }

    public function test_indicator_parser_requires_version_first_and_id(): void
    {
        $parser = new MtaStsDnsRecordParser();
        $parsed = $parser->parse('v=STSv1; id=abc123;');

        $this->assertTrue($parsed->versionFirst);
        $this->assertSame('abc123', $parsed->id);
        $this->assertTrue($parser->isValidId($parsed->id));
    }

    public function test_policy_parser_multiple_mx_lines(): void
    {
        $parser = new MtaStsPolicyParser();
        $parsed = $parser->parse("version: STSv1\nmode: enforce\nmax_age: 604800\nmx: *.mail.example.com\nmx: mx2.mail.example.com\n");

        $this->assertSame('enforce', $parsed->mode);
        $this->assertSame(604800, $parsed->maxAge);
        $this->assertCount(2, $parsed->mxPatterns);
    }

    public function test_missing_indicator_scores_zero(): void
    {
        $native = new MtaStsNativeResult(
            state: MtaStsStates::MISSING,
            protocolStatus: MtaStsProtocolStatus::NONE,
            riskStatus: MtaStsRiskStatus::WARNING,
            summary: 'missing',
            domain: 'example.com',
            evaluationCompleteness: 'complete',
        );

        $this->assertSame(0, (new MtaStsScoreRule())->score($native)->earned);
    }

    public function test_mode_none_scores_four(): void
    {
        $native = new MtaStsNativeResult(
            state: MtaStsStates::WARNING,
            protocolStatus: MtaStsProtocolStatus::VALID,
            riskStatus: MtaStsRiskStatus::WARNING,
            summary: 'none',
            domain: 'example.com',
            evaluationCompleteness: 'complete',
            policy: ['mode' => 'none'],
        );

        $this->assertSame(4, (new MtaStsScoreRule())->score($native)->earned);
    }
}
