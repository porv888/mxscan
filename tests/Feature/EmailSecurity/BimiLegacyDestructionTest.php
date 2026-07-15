<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class BimiLegacyDestructionTest extends TestCase
{
    public function test_bimi_checker_service_removed(): void
    {
        $this->assertFileDoesNotExist(app_path('Services/BimiChecker.php'));
    }

    public function test_scanner_service_has_no_bimi_checker_invocation(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScannerService.php'));
        $this->assertStringNotContainsString('BimiChecker', $source);
    }

    public function test_bundled_adapter_has_no_bimi_mapping(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString('ScanRecordKeys::BIMI', $source);
    }

    public function test_no_bimi_engine_config_exists(): void
    {
        $this->assertNull(config('email-security.bimi_engine'));
    }

    public function test_bimi_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('BimiCheck::class', $source);
        $this->assertStringContainsString('registerNativeBimiServices', $source);
    }

    public function test_bimi_analysis_reader_has_no_network_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Bimi/BimiAnalysisReader.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('Http::', $source);
    }

    public function test_tools_controller_does_not_use_bimi_checker(): void
    {
        $source = (string) file_get_contents(app_path('Http/Controllers/ToolsController.php'));
        $this->assertStringNotContainsString('BimiChecker', $source);
        $this->assertStringContainsString('BimiAnalysisService', $source);
    }

    public function test_public_scan_view_has_no_remote_logo_links_or_embeds(): void
    {
        $source = (string) file_get_contents(resource_path('views/public/scan-result.blade.php'));
        $this->assertStringNotContainsString('logo_url', $source);
        $this->assertStringNotContainsString('<img src="http', $source);
    }
}
