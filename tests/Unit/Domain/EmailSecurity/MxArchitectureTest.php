<?php

namespace Tests\Unit\Domain\EmailSecurity;

use Tests\TestCase;

class MxArchitectureTest extends TestCase
{
    public function test_deleted_mta_sts_mx_evidence_provider_no_longer_exists(): void
    {
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Evidence/MtaStsMxEvidenceProvider.php'));
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Contracts/MtaStsMxEvidenceProviderInterface.php'));
    }

    public function test_bundled_dns_adapter_has_no_mx_mapping(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/BundledDnsChecksAdapter.php'));
        $this->assertStringNotContainsString('ScanRecordKeys::MX', $source);
    }

    public function test_score_breakdown_service_has_no_score_mx(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScoreBreakdownService.php'));
        $this->assertStringNotContainsString('function scoreMx', $source);
    }

    public function test_scanner_service_has_no_dns_mx_lookup(): void
    {
        $source = (string) file_get_contents(app_path('Services/ScannerService.php'));
        $this->assertStringNotContainsString('DNS_MX', $source);
    }

    public function test_mta_sts_evidence_builder_has_no_dns_get_record_mx(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/MtaSts/Evidence/MtaStsEvidenceBuilder.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('MtaStsMxEvidenceProvider', $source);
    }

    public function test_mx_check_is_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('MxCheck::class', $source);
        $this->assertStringContainsString('registerNativeMxServices', $source);
        $this->assertStringNotContainsString('MX_ENGINE', $source);
    }

    public function test_no_mx_engine_config_key_exists(): void
    {
        $this->assertNull(config('email-security.mx_engine'));
    }

    public function test_mx_analysis_reader_legacy_path_has_no_dns_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Mx/Support/MxAnalysisReader.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('MxDnsResolver', $source);
    }

    public function test_mx_module_has_no_smtp_or_certificate_imports(): void
    {
        $mxRoot = app_path('Domain/EmailSecurity/Checks/Mx');
        foreach (glob($mxRoot . '/**/*.php') ?: [] as $file) {
            $source = (string) file_get_contents($file);
            $this->assertStringNotContainsString('MtaStsSmtp', $source, basename($file));
            $this->assertStringNotContainsString('CertificateInspector', $source, basename($file));
        }
    }

    public function test_dns_section_presenter_mx_detail_does_not_parse_raw_mx_data(): void
    {
        $source = (string) file_get_contents(app_path('View/Presenters/DnsSectionPresenter.php'));
        $this->assertStringContainsString('MxAnalysisReader', $source);
        $this->assertStringContainsString('function mxDetail', $source);
        $this->assertStringNotContainsString("records['MX']['data']", $source);
    }

    public function test_scan_recommendation_service_delegates_mx_to_evaluator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Recommendations/ScanRecommendationService.php'));
        $this->assertStringContainsString('MxRecommendationEvaluator', $source);
        $this->assertStringContainsString('mxRecommendationEvaluator->evaluate', $source);
    }

    public function test_mx_check_delegates_to_mx_analysis_service(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Mx/MxCheck.php'));
        $this->assertStringContainsString('MxAnalysisService', $source);
        $this->assertStringContainsString('analysisService->analyze', $source);
    }

    public function test_http_controllers_do_not_parse_raw_mx_records(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(app_path('Http/Controllers'))
        );

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $source = (string) file_get_contents($file->getPathname());
            $this->assertStringNotContainsString("records['MX']['data']", $source, $file->getFilename());
            $this->assertStringNotContainsString('DNS_MX', $source, $file->getFilename());
        }
    }
}
