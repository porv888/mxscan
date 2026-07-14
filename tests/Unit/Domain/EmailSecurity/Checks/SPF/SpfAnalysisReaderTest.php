<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Support\SpfAnalysisReader;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use Tests\TestCase;

class SpfAnalysisReaderTest extends TestCase
{
    public function test_prefers_analysis_fields_over_top_level(): void
    {
        $spf = [
            'protocol_status' => 'legacy-top',
            'ui_state' => 'legacy-ui',
            'summary' => 'legacy summary',
            'analysis' => [
                'protocol_status' => 'valid',
                'risk_status' => 'healthy',
                'state' => 'pass',
                'summary' => 'native summary',
                'terminal_policy' => SpfTerminalPolicy::HARD_FAIL,
                'evaluation_completeness' => 'complete',
                'errors' => [],
                'warnings' => [['code' => 'DEPRECATED_PTR', 'message' => 'x']],
                'dependencies' => [['mechanism' => 'include', 'domain' => 'a.test']],
            ],
        ];

        $this->assertSame('valid', SpfAnalysisReader::protocolStatus($spf));
        $this->assertSame('healthy', SpfAnalysisReader::riskStatus($spf));
        $this->assertSame('pass', SpfAnalysisReader::state($spf));
        $this->assertSame('native summary', SpfAnalysisReader::summary($spf));
        $this->assertSame(SpfTerminalPolicy::HARD_FAIL, SpfAnalysisReader::terminalPolicy($spf));
        $this->assertSame('complete', SpfAnalysisReader::evaluationCompleteness($spf));
        $this->assertCount(1, SpfAnalysisReader::warnings($spf));
        $this->assertSame('include', SpfAnalysisReader::dependencies($spf)[0]['mechanism']);
    }

    public function test_falls_back_to_top_level_for_historical_scans(): void
    {
        $spf = [
            'protocol_status' => 'valid',
            'risk_status' => 'warning',
            'ui_state' => 'warning',
            'summary' => 'historical summary',
        ];

        $this->assertSame('valid', SpfAnalysisReader::protocolStatus($spf));
        $this->assertSame('warning', SpfAnalysisReader::riskStatus($spf));
        $this->assertSame('warning', SpfAnalysisReader::state($spf));
        $this->assertSame('historical summary', SpfAnalysisReader::summary($spf));
        $this->assertNull(SpfAnalysisReader::terminalPolicy($spf));
    }
}
