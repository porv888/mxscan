<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Recommendations\SpfRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Services\Spf\SpfResolver;
use Tests\TestCase;

class SpfRecommendationEvaluatorTest extends TestCase
{
    public function test_generates_replace_deprecated_ptr_recommendation(): void
    {
        $mapper = new ScanReportStatusMapper();
        $spfInfo = [
            'record' => 'v=spf1 ptr -all',
            'lookups' => 1,
            'valid' => true,
            'warnings' => [SpfResolver::WARNING_PTR_USED],
            'protocol_status' => 'valid',
            'risk_status' => 'warning',
            'ui_state' => 'warning',
        ];
        $card = $mapper->mapSpf(['status' => 'found', 'data' => $spfInfo['record']], $spfInfo);

        $items = (new SpfRecommendationEvaluator())->evaluate(
            ['status' => 'found', 'data' => $spfInfo['record']],
            $card,
            $spfInfo,
        );

        $this->assertTrue(collect($items)->contains(fn ($item) => $item['semantic_key'] === 'replace_deprecated_ptr'));
    }

    public function test_weak_terminal_policy_from_analysis_not_raw_record(): void
    {
        $mapper = new ScanReportStatusMapper();
        $spfInfo = [
            'record' => 'v=spf1 -all',
            'lookups' => 1,
            'valid' => true,
            'warnings' => [],
            'status' => 'safe',
            'analysis' => [
                'version' => 'spf-native-v1',
                'protocol_status' => 'valid',
                'risk_status' => 'healthy',
                'state' => 'pass',
                'summary' => 'valid',
                'terminal_policy' => SpfTerminalPolicy::SOFT_FAIL,
                'lookup_count' => 1,
                'lookup_limit' => 10,
                'lookups_remaining' => 9,
                'void_lookup_count' => 0,
                'evaluation_completeness' => 'complete',
                'errors' => [],
                'warnings' => [],
                'dependencies' => [],
            ],
        ];
        $card = $mapper->mapSpf(['status' => 'found', 'data' => $spfInfo['record']], $spfInfo);

        $items = (new SpfRecommendationEvaluator())->evaluate(
            ['status' => 'found', 'data' => $spfInfo['record']],
            $card,
            $spfInfo,
        );

        $this->assertTrue(collect($items)->contains(fn ($item) => $item['semantic_key'] === 'review_weak_terminal_policy'));
    }

    public function test_historical_scan_without_terminal_policy_skips_weak_terminal_recommendation(): void
    {
        $mapper = new ScanReportStatusMapper();
        $spfInfo = [
            'record' => 'v=spf1 ~all',
            'lookups' => 1,
            'valid' => true,
            'warnings' => [],
            'protocol_status' => 'valid',
            'ui_state' => 'pass',
        ];
        $card = $mapper->mapSpf(['status' => 'found', 'data' => $spfInfo['record']], $spfInfo);

        $items = (new SpfRecommendationEvaluator())->evaluate(
            ['status' => 'found', 'data' => $spfInfo['record']],
            $card,
            $spfInfo,
        );

        $this->assertFalse(collect($items)->contains(fn ($item) => $item['semantic_key'] === 'review_weak_terminal_policy'));
    }
}
