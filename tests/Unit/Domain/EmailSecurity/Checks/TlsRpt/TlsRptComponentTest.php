<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\TlsRpt;

use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptDestinationParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptRecordParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptTxtReconstructor;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptRiskStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptDestinationValidator;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptRecordValidator;
use App\Domain\EmailSecurity\Scoring\Rules\TlsRptScoreRule;
use Tests\TestCase;

class TlsRptComponentTest extends TestCase
{
    public function test_joins_multi_string_txt_within_one_rr(): void
    {
        $joined = TlsRptTxtReconstructor::fromDnsRow([
            'txt' => ['v=TLSRPTv1;', ' rua=mailto:a@example.test'],
        ]);

        $this->assertSame('v=TLSRPTv1; rua=mailto:a@example.test', $joined);
    }

    public function test_selects_exact_version_token_and_rejects_v10(): void
    {
        $records = [
            'v=TLSRPTv1; rua=mailto:a@example.test',
            'v=TLSRPTv10; rua=mailto:b@example.test',
            'not-tls-rpt',
        ];

        $selected = TlsRptTxtReconstructor::selectTlsRptRecords($records);
        $this->assertSame(['v=TLSRPTv1; rua=mailto:a@example.test'], $selected);
    }

    public function test_parser_requires_version_first_and_rua(): void
    {
        $parser = new TlsRptRecordParser();
        $validator = new TlsRptRecordValidator($parser);

        $missingRua = $validator->validateParsed($parser->parse('v=TLSRPTv1'));
        $this->assertFalse($missingRua->valid);
        $this->assertSame('MISSING_RUA', $missingRua->errors[0]['code'] ?? null);
    }

    public function test_mailto_and_https_destinations(): void
    {
        $parser = new TlsRptDestinationParser();
        $validator = new TlsRptDestinationValidator($parser);

        $result = $validator->validate('mailto:tls@example.test,https://reports.example.test/tls');
        $this->assertTrue($result->configured);
        $this->assertSame(2, $result->validCount);
    }

    public function test_rejects_http_scheme(): void
    {
        $parser = new TlsRptDestinationParser();
        $destination = $parser->parseOne('http://reports.example.test/tls');

        $this->assertSame('invalid', $destination->status);
    }

    public function test_duplicate_destination_detection(): void
    {
        $parser = new TlsRptDestinationParser();
        $validator = new TlsRptDestinationValidator($parser);
        $result = $validator->validate('mailto:tls@example.test,mailto:tls@example.test');

        $this->assertTrue($result->hasMaterialWarnings);
        $this->assertTrue($result->destinations[1]->duplicate);
    }

    public function test_scoring_table(): void
    {
        $rule = new TlsRptScoreRule();

        $missing = new TlsRptNativeResult(
            state: TlsRptStates::MISSING,
            protocolStatus: TlsRptProtocolStatus::NONE,
            riskStatus: TlsRptRiskStatus::WARNING,
            summary: 'missing',
            domain: 'example.test',
            recordHostname: '_smtp._tls.example.test',
            evaluationCompleteness: 'complete',
        );
        $this->assertSame(0, $rule->score($missing)->earned);

        $temperror = new TlsRptNativeResult(
            state: TlsRptStates::UNKNOWN,
            protocolStatus: TlsRptProtocolStatus::TEMPERROR,
            riskStatus: TlsRptRiskStatus::UNKNOWN,
            summary: 'temperror',
            domain: 'example.test',
            recordHostname: '_smtp._tls.example.test',
            evaluationCompleteness: 'failed',
        );
        $this->assertSame(2, $rule->score($temperror)->earned);

        $warning = new TlsRptNativeResult(
            state: TlsRptStates::WARNING,
            protocolStatus: TlsRptProtocolStatus::VALID,
            riskStatus: TlsRptRiskStatus::WARNING,
            summary: 'warning',
            domain: 'example.test',
            recordHostname: '_smtp._tls.example.test',
            evaluationCompleteness: 'complete',
            hasMaterialWarnings: true,
        );
        $this->assertSame(4, $rule->score($warning)->earned);

        $pass = new TlsRptNativeResult(
            state: TlsRptStates::PASS,
            protocolStatus: TlsRptProtocolStatus::VALID,
            riskStatus: TlsRptRiskStatus::HEALTHY,
            summary: 'pass',
            domain: 'example.test',
            recordHostname: '_smtp._tls.example.test',
            evaluationCompleteness: 'complete',
        );
        $this->assertSame(5, $rule->score($pass)->earned);
    }
}
