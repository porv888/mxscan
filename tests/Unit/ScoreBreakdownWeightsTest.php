<?php

namespace Tests\Unit;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsRiskStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptRiskStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Scoring\Rules\MxScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\MtaStsScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\TlsRptScoreRule;
use App\Services\ScoreBreakdownService;
use Tests\TestCase;

class ScoreBreakdownWeightsTest extends TestCase
{
    public function test_exact_new_component_weights_and_bimi_never_deducts(): void
    {
        $service = new ScoreBreakdownService();

        $missingAll = $service->buildFromDnsRecords([
            'MX' => ['status' => 'missing'],
            'SPF' => ['status' => 'missing'],
            'DKIM' => ['status' => 'missing'],
            'DMARC' => ['status' => 'missing'],
            'TLS-RPT' => ['status' => 'missing'],
            'MTA-STS' => ['status' => 'missing'],
            'BIMI' => ['status' => 'missing'],
        ]);

        $byKey = collect($missingAll)->keyBy('key');
        $this->assertSame(20, $byKey['spf']['possible']);
        $this->assertFalse($byKey->has('mx'));
        $this->assertFalse($byKey->has('dkim'));
        $this->assertFalse($byKey->has('dmarc'));
        $this->assertFalse($byKey->has('tlsrpt'));
        $this->assertFalse($byKey->has('mtasts'));
        $this->assertSame(0, $byKey['bimi']['possible']);
        $this->assertSame(0, $byKey['bimi']['earned']);
        $this->assertSame('DKIM DNS configuration', config('dns-scoring.dkim.label'));
        $this->assertSame(10, config('dns-scoring.mtasts.max'));

        $mxRule = new MxScoreRule();
        $missingMx = new MxNativeResult(
            state: MxStates::FAIL,
            protocolStatus: MxProtocolStatus::NONE,
            riskStatus: MxRiskStatus::CRITICAL,
            summary: 'No MX records were found.',
            domain: 'example.test',
            serviceMode: MxServiceMode::UNKNOWN,
            dnsStatus: 'missing',
            recordsTotal: 0,
            usableTargets: 0,
            invalidTargets: 0,
            nullMx: ['valid' => false],
            implicitFallback: ['active' => false],
            preferenceGroups: [],
            targets: [],
            evaluationCompleteness: 'complete',
        );
        $this->assertSame(15, $mxRule->score($missingMx)->possible);
        $this->assertSame(0, $mxRule->score($missingMx)->earned);

        $mtaStsRule = new MtaStsScoreRule();
        $missingNative = new MtaStsNativeResult(
            state: MtaStsStates::MISSING,
            protocolStatus: MtaStsProtocolStatus::NONE,
            riskStatus: MtaStsRiskStatus::WARNING,
            summary: 'No MTA-STS DNS indicator was found.',
            domain: 'example.test',
            evaluationCompleteness: 'complete',
        );
        $this->assertSame(10, $mtaStsRule->score($missingNative)->possible);
        $this->assertSame(0, $mtaStsRule->score($missingNative)->earned);

        $tlsRptRule = new TlsRptScoreRule();
        $missingTlsRpt = new TlsRptNativeResult(
            state: TlsRptStates::MISSING,
            protocolStatus: TlsRptProtocolStatus::NONE,
            riskStatus: TlsRptRiskStatus::WARNING,
            summary: 'No TLS-RPT policy was found.',
            domain: 'example.test',
            recordHostname: '_smtp._tls.example.test',
            evaluationCompleteness: 'complete',
        );
        $this->assertSame(5, $tlsRptRule->score($missingTlsRpt)->possible);
        $this->assertSame(0, $tlsRptRule->score($missingTlsRpt)->earned);

        $deductions = $service->deductions($missingAll);
        $this->assertFalse(collect($deductions)->contains(fn ($r) => $r['key'] === 'bimi'));

        $spfLoss = $byKey['spf']['possible'] - $byKey['spf']['earned'];
        $mtaLoss = $mtaStsRule->score($missingNative)->possible - $mtaStsRule->score($missingNative)->earned;
        $this->assertGreaterThan($mtaLoss, $spfLoss);

        $perfect = $service->buildFromDnsRecords([
            'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
            'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
            'TLS-RPT' => ['status' => 'found', 'data' => 'v=TLSRPTv1'],
            'MTA-STS' => ['status' => 'missing'],
            'BIMI' => ['status' => 'missing'],
        ]);
        $validMx = new MxNativeResult(
            state: MxStates::PASS,
            protocolStatus: MxProtocolStatus::VALID,
            riskStatus: MxRiskStatus::HEALTHY,
            summary: 'MX records are configured.',
            domain: 'example.test',
            serviceMode: MxServiceMode::ACCEPTS_MAIL,
            dnsStatus: 'found',
            recordsTotal: 1,
            usableTargets: 1,
            invalidTargets: 0,
            nullMx: ['valid' => false],
            implicitFallback: ['active' => false],
            preferenceGroups: [],
            targets: [],
            evaluationCompleteness: 'complete',
        );
        $total = $service->totalEarned($perfect) + $mxRule->score($validMx)->earned;
        $this->assertSame(35, $total);
        $this->assertGreaterThanOrEqual(0, $total);
        $this->assertLessThanOrEqual(100, $total);
    }
}
