<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class DkimLegacyDestructionTest extends TestCase
{
    public function test_scanner_service_has_no_dkim_selector_loop(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScannerService.php'));
        $this->assertStringNotContainsString('_domainkey.', $source);
        $this->assertStringNotContainsString('dkimSelectors', $source);
    }

    public function test_score_breakdown_no_longer_contains_score_dkim_method(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScoreBreakdownService.php'));
        $this->assertStringNotContainsString('function scoreDkim', $source);
    }

    public function test_bundled_adapter_no_longer_maps_dkim(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString('ScanRecordKeys::DKIM', $source);
    }

    public function test_dkim_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('DkimCheck::class', $source);
        $this->assertStringNotContainsString('resolveDkimCheck', $source);
    }

    public function test_tools_controller_uses_dkim_analysis_service(): void
    {
        $source = (string) file_get_contents(app_path('Http/Controllers/ToolsController.php'));
        $this->assertStringContainsString('DkimAnalysisService', $source);
        $this->assertStringNotContainsString('parseDkimPublicKey', $source);
    }

    public function test_recommendation_service_uses_dkim_evaluator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Recommendations/ScanRecommendationService.php'));
        $this->assertStringContainsString('DkimRecommendationEvaluator', $source);
        $this->assertStringNotContainsString("'dkim_dns'", $source);
    }
}
