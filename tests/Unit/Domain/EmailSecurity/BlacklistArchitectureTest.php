<?php

namespace Tests\Unit\Domain\EmailSecurity;

use Tests\TestCase;

class BlacklistArchitectureTest extends TestCase
{
    public function test_blacklist_checker_service_deleted(): void
    {
        $this->assertFileDoesNotExist(app_path('Services/BlacklistChecker.php'));
    }

    public function test_no_blacklist_checker_instantiation_in_app(): void
    {
        $paths = [
            app_path('Http'),
            app_path('Domain/EmailSecurity'),
            app_path('Jobs'),
            app_path('Console'),
        ];

        foreach ($paths as $path) {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }
                $source = (string) file_get_contents($file->getPathname());
                $this->assertStringNotContainsString('new BlacklistChecker(', $source, $file->getFilename());
            }
        }
    }

    public function test_blacklist_module_has_no_dns_mx_lookup(): void
    {
        $path = app_path('Domain/EmailSecurity/Checks/Blacklist');
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $source = (string) file_get_contents($file->getPathname());
            $this->assertStringNotContainsString('DNS_MX', $source, $file->getFilename());
            $this->assertStringNotContainsString("records['MX']", $source, $file->getFilename());
        }
    }

    public function test_blacklist_check_delegates_to_orchestrator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Blacklist/BlacklistCheck.php'));
        $this->assertStringContainsString('BlacklistScanOrchestrator', $source);
        $this->assertStringContainsString('orchestrator->run', $source);
    }

    public function test_scan_recommendation_service_delegates_blacklist_to_evaluator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Recommendations/ScanRecommendationService.php'));
        $this->assertStringContainsString('BlacklistRecommendationEvaluator', $source);
        $this->assertStringContainsString('blacklistRecommendationEvaluator->evaluate', $source);
        $this->assertStringNotContainsString("semanticKey: 'blacklist'", $source);
        $this->assertStringNotContainsString('remove_from_blacklists', $source);
    }

    public function test_no_blacklist_score_rule_in_weighted_calculator(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Scoring/LegacyDnsScoreCalculator.php'));
        $this->assertStringNotContainsString('BlacklistScoreRule', $source);
        $this->assertStringNotContainsString('scoreBlacklist', $source);
    }

    public function test_no_blacklist_engine_config(): void
    {
        $this->assertNull(config('email-security.blacklist_engine'));
    }

    public function test_provider_registry_is_sole_provider_source_in_module(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Blacklist/BlacklistEvidenceBuilder.php'));
        $this->assertStringContainsString('BlacklistProviderRegistry', $source);
        $this->assertStringNotContainsString("config('rbl.providers'", $source);
    }

    public function test_run_blacklist_scan_job_exists(): void
    {
        $this->assertFileExists(app_path('Jobs/RunBlacklistScan.php'));
    }

    public function test_public_scan_controller_disables_blacklist(): void
    {
        $source = (string) file_get_contents(app_path('Http/Controllers/PublicScanController.php'));
        $this->assertStringContainsString("'blacklist' => false", $source);
    }

    public function test_blacklist_analysis_reader_has_no_dns_calls(): void
    {
        $source = (string) file_get_contents(app_path('Domain/EmailSecurity/Checks/Blacklist/Support/BlacklistAnalysisReader.php'));
        $this->assertStringNotContainsString('dns_get_record', $source);
        $this->assertStringNotContainsString('BlacklistDnsResolver', $source);
    }
}
