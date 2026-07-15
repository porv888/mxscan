<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class CertificateNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    public function test_certificate_analysis_persisted_in_result_json(): void
    {
        config(['email-security.spf_engine' => 'legacy']);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        CertificateTestProbeFactory::bindFakeProbes();
        FixtureLoader::bindDnsCollector(FixtureLoader::input('dns-bundled-full'));
        FixtureLoader::bindMxFixtures(FixtureLoader::input('dns-bundled-full'), 'example.test');
        FixtureLoader::bindMtaStsFixtures();

        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        $execution = app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => false, 'blacklist' => false]),
            microtime(true),
        );

        $analysis = $execution->resultJson['certificates']['analysis'] ?? null;
        $this->assertIsArray($analysis);
        $this->assertSame('certificates-native-v1', $analysis['version'] ?? null);
        $this->assertNotEmpty($analysis['endpoints'] ?? []);
        $this->assertContains($analysis['state'] ?? null, [
            CertificateStates::PASS,
            CertificateStates::WARNING,
            CertificateStates::FAIL,
            CertificateStates::UNKNOWN,
        ]);
    }
}
