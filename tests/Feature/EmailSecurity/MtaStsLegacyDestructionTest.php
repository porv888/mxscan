<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class MtaStsLegacyDestructionTest extends TestCase
{
    public function test_scanner_service_has_no_mta_sts_http_fetch(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScannerService.php'));
        $this->assertStringNotContainsString('Http::', $source);
        $this->assertStringNotContainsString('mta-sts.txt', $source);
        $this->assertStringNotContainsString('dns-scoring.mtasts.full', $source);
    }

    public function test_score_breakdown_no_longer_contains_score_mta_sts_method(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScoreBreakdownService.php'));
        $this->assertStringNotContainsString('function scoreMtaSts', $source);
    }

    public function test_bundled_adapter_no_longer_maps_mta_sts(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString('ScanRecordKeys::MTA_STS', $source);
    }

    public function test_no_mta_sts_engine_config_exists(): void
    {
        $this->assertNull(config('email-security.mta_sts_engine'));
    }

    public function test_mta_sts_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('MtaStsCheck::class', $source);
        $this->assertStringContainsString('registerNativeMtaStsServices', $source);
    }

    public function test_mta_sts_analysis_reader_has_no_network_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/MtaSts/Support/MtaStsAnalysisReader.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('Http::', $source);
        $this->assertStringNotContainsString('fsockopen', $source);
    }
}
