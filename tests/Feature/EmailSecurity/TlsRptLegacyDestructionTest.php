<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class TlsRptLegacyDestructionTest extends TestCase
{
    public function test_scanner_service_has_no_tls_rpt_scoring(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScannerService.php'));
        $this->assertStringNotContainsString('dns-scoring.tlsrpt.max', $source);
    }

    public function test_score_breakdown_no_longer_contains_score_tls_rpt_method(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScoreBreakdownService.php'));
        $this->assertStringNotContainsString('function scoreTlsRpt', $source);
    }

    public function test_bundled_adapter_no_longer_maps_tls_rpt(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString('ScanRecordKeys::TLS_RPT', $source);
    }

    public function test_no_tls_rpt_engine_config_exists(): void
    {
        $this->assertNull(config('email-security.tls_rpt_engine'));
    }

    public function test_tls_rpt_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('TlsRptCheck::class', $source);
        $this->assertStringContainsString('registerNativeTlsRptServices', $source);
    }

    public function test_tls_rpt_analysis_reader_has_no_network_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/TlsRpt/Support/TlsRptAnalysisReader.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('Http::', $source);
        $this->assertStringNotContainsString('mail(', $source);
    }

    public function test_tls_rpt_module_has_no_destination_fetch(): void
    {
        $glob = glob(app_path('Domain/EmailSecurity/Checks/TlsRpt/**/*.php')) ?: [];
        foreach ($glob as $file) {
            $source = (string) file_get_contents($file);
            $this->assertStringNotContainsString('Http::', $source, basename($file));
            $this->assertStringNotContainsString('mail(', $source, basename($file));
        }
    }
}
