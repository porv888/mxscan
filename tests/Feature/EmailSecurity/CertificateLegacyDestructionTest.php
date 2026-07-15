<?php

namespace Tests\Feature\EmailSecurity;

use Tests\TestCase;

class CertificateLegacyDestructionTest extends TestCase
{
    public function test_deleted_mta_sts_tls_inspector_classes_no_longer_exist(): void
    {
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Tls/MtaStsPolicyCertificateInspector.php'));
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Tls/MtaStsSmtpMxInspector.php'));
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Contracts/MtaStsCertificateInspectorInterface.php'));
        $this->assertFileDoesNotExist(app_path('Domain/EmailSecurity/Checks/MtaSts/Contracts/MtaStsSmtpInspectorInterface.php'));
    }

    public function test_deleted_expiry_probe_classes_no_longer_exist(): void
    {
        $this->assertFileDoesNotExist(app_path('Services/Expiry/Providers/LiveTlsProvider.php'));
        $this->assertFileDoesNotExist(app_path('Support/SslInspector.php'));
        $this->assertFileDoesNotExist(app_path('Services/ExpiryService.php'));
        $this->assertFileDoesNotExist(app_path('Jobs/CheckExpiries.php'));
        $this->assertFileDoesNotExist(app_path('Jobs/CheckExpiryReminders.php'));
    }

    public function test_certificate_section_presenter_has_no_network_or_openssl_calls(): void
    {
        $source = (string) file_get_contents(app_path('View/Presenters/CertificateSectionPresenter.php'));
        $this->assertStringNotContainsString('stream_socket_client', $source);
        $this->assertStringNotContainsString('openssl_x509_parse', $source);
        $this->assertStringNotContainsString('fsockopen', $source);
    }
}
