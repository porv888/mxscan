<?php

namespace Tests\Unit;

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
        $this->assertSame(15, $byKey['mx']['possible']);
        $this->assertSame(20, $byKey['spf']['possible']);
        $this->assertSame(20, $byKey['dkim']['possible']);
        $this->assertSame(30, $byKey['dmarc']['possible']);
        $this->assertSame(5, $byKey['tlsrpt']['possible']);
        $this->assertSame(10, $byKey['mtasts']['possible']);
        $this->assertSame(0, $byKey['bimi']['possible']);
        $this->assertSame(0, $byKey['bimi']['earned']);
        $this->assertSame('DKIM DNS configuration', $byKey['dkim']['label']);

        $deductions = $service->deductions($missingAll);
        $this->assertFalse(collect($deductions)->contains(fn ($r) => $r['key'] === 'bimi'));

        $spfLoss = $byKey['spf']['possible'] - $byKey['spf']['earned'];
        $mtaLoss = $byKey['mtasts']['possible'] - $byKey['mtasts']['earned'];
        $this->assertGreaterThan($mtaLoss, $spfLoss);

        $perfect = $service->buildFromDnsRecords([
            'MX' => ['status' => 'found', 'data' => []],
            'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
            'DKIM' => ['status' => 'found', 'data' => [['selector' => 's1']]],
            'DMARC' => ['status' => 'found', 'data' => 'v=DMARC1; p=reject'],
            'TLS-RPT' => ['status' => 'found', 'data' => 'v=TLSRPTv1'],
            'MTA-STS' => ['status' => 'found', 'data' => 'v=STSv1', 'policy' => 'version: STSv1'],
            'BIMI' => ['status' => 'missing'],
        ]);
        $total = $service->totalEarned($perfect);
        $this->assertSame(100, $total);
        $this->assertGreaterThanOrEqual(0, $total);
        $this->assertLessThanOrEqual(100, $total);
    }
}
