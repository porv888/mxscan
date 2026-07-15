<?php

namespace Tests\Unit\Domain\EmailSecurity;

use Tests\TestCase;

class CertificateArchitectureTest extends TestCase
{
    public function test_deleted_mta_sts_certificate_inspector_no_longer_exists(): void
    {
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Tls/MtaStsPolicyCertificateInspector.php'));
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Tls/MtaStsSmtpMxInspector.php'));
    }

    public function test_deleted_live_tls_provider_no_longer_exists(): void
    {
        $this->assertFileDoesNotExist(app_path('Services/Expiry/Providers/LiveTlsProvider.php'));
        $this->assertFileDoesNotExist(app_path('Support/SslInspector.php'));
    }

    public function test_no_certificate_engine_config_exists(): void
    {
        $this->assertNull(config('email-security.certificate_engine'));
        $this->assertNull(config('email-security.ssl_engine'));
    }

    public function test_certificate_check_registered_in_provider(): void
    {
        $source = (string) file_get_contents(app_path('Providers/EmailSecurityServiceProvider.php'));
        $this->assertStringContainsString('CertificateCheck::class', $source);
        $this->assertStringContainsString('registerNativeCertificateServices', $source);
    }

    public function test_certificate_analysis_reader_has_no_network_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Certificates/Support/CertificateAnalysisReader.php'));
        $this->assertStringNotContainsString('stream_socket_client', $source);
        $this->assertStringNotContainsString('fsockopen', $source);
        $this->assertStringNotContainsString('Http::', $source);
    }

    public function test_certificate_check_delegates_to_analysis_service(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Certificates/CertificateCheck.php'));
        $this->assertStringContainsString('CertificateAnalysisService', $source);
        $this->assertStringContainsString('analysisService->analyze', $source);
    }

    public function test_scan_recommendation_service_delegates_certificates_to_evaluator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Recommendations/ScanRecommendationService.php'));
        $this->assertStringContainsString('CertificateRecommendationEvaluator', $source);
        $this->assertStringContainsString('certificateRecommendationEvaluator->evaluate', $source);
    }
}
