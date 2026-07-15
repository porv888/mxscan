<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class DmarcLegacyDestructionTest extends TestCase
{
    public function test_legacy_dmarc_dns_lookup_class_removed(): void
    {
        $this->assertFileDoesNotExist(app_path('Services/Dmarc/DmarcDnsLookup.php'));
    }

    public function test_legacy_run_scan_job_removed(): void
    {
        $this->assertFileDoesNotExist(app_path('Jobs/RunScan.php'));
    }

    public function test_score_breakdown_no_longer_contains_score_dmarc_method(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScoreBreakdownService.php'));
        $this->assertStringNotContainsString('function scoreDmarc', $source);
    }

    public function test_bundled_adapter_no_longer_maps_dmarc(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString("ScanRecordKeys::DMARC", $source);
    }

    public function test_no_dmarc_engine_config_exists(): void
    {
        $this->assertNull(config('email-security.dmarc_engine'));
        $envExample = (string) file_get_contents(base_path('.env.example'));
        $this->assertStringNotContainsString('DMARC_ENGINE', $envExample);
    }

    public function test_dmarc_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('DmarcCheck::class', $source);
        $this->assertStringNotContainsString('resolveDmarcCheck', $source);
    }

    public function test_dmarc_recommendation_evaluator_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('DmarcRecommendationEvaluator::class', $source);
    }

    public function test_dmarc_status_service_uses_analysis_reader(): void
    {
        $source = (string) file_get_contents(app_path('Services/Dmarc/DmarcStatusService.php'));
        $this->assertStringContainsString('DmarcAnalysisReader', $source);
        $this->assertStringContainsString('classifyFromAnalysis', (string) file_get_contents(app_path('Services/Dmarc/DmarcRuaClassifier.php')));
    }

    public function test_dmarc_status_service_live_dns_only_parses_records(): void
    {
        $source = (string) file_get_contents(app_path('Services/Dmarc/DmarcStatusService.php'));
        $this->assertStringNotContainsString('parsedTags(', $source);

        preg_match('/protected function hasRuaInDmarc\(Domain \$domain\): bool\s*\{[^}]*\}/s', $source, $hasRua);
        $this->assertStringNotContainsString('parseLiveDnsRecord(', $hasRua[0] ?? '');

        preg_match(
            '/protected function classifyDomainRua\(Domain \$domain\): array\s*\{.*?\n    \}\n\n    protected function resolveDmarcContext/s',
            $source,
            $classify,
        );
        $this->assertStringNotContainsString('parseLiveDnsRecord(', $classify[0] ?? '');

        preg_match(
            '/public function checkDnsAndSync\(Domain \$domain\): array\s*\{.*?\n    \}\n\n    \/\*\*/s',
            $source,
            $dns,
        );
        $this->assertSame(1, substr_count($dns[0] ?? '', 'parseLiveDnsRecord('));
    }

    public function test_parse_dmarc_tags_removed_from_classifier(): void
    {
        $source = (string) file_get_contents(app_path('Services/Dmarc/DmarcRuaClassifier.php'));
        $this->assertStringNotContainsString('function parseDmarcTags', $source);
    }
}
