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

    public function test_partially_evaluated_macro_prefers_specific_recommendation_only(): void
    {
        $spfInfo = json_decode(
            (string) file_get_contents(base_path('tests/Fixtures/EmailSecurity/inputs/spf-salesforce-partial.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        $mapper = new ScanReportStatusMapper();
        $card = $mapper->mapSpf(['status' => 'found', 'data' => $spfInfo['record']], $spfInfo);

        $items = (new SpfRecommendationEvaluator())->evaluate(
            ['status' => 'found', 'data' => $spfInfo['record']],
            $card,
            $spfInfo,
        );

        $semanticKeys = array_column($items, 'semantic_key');
        $this->assertSame(['review_unsupported_spf_macro'], $semanticKeys);
        $this->assertFalse(in_array('review_weak_terminal_policy', $semanticKeys, true));
        $this->assertFalse(in_array('fix_invalid_spf', $semanticKeys, true));
    }
}
