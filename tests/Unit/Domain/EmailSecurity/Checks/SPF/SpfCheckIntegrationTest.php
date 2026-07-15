<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\SpfCheck;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\JsonParityNormalizer;
use Tests\TestCase;

class SpfCheckIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['email-security.spf_engine' => 'native']);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
    }

    public function test_native_spf_check_matches_configured_fixture_shape(): void
    {
        $spfPayload = FixtureLoader::input('spf-configured');
        $dns = new DnsCollectionResultDTO(
            records: FixtureLoader::input('dns-bundled-full')['records'],
            score: 75,
            scoreBreakdown: [],
            legacyDnsPayload: FixtureLoader::input('dns-bundled-full'),
            rootTxtRecords: [
                ['host' => 'example.test', 'txt' => $spfPayload['record'], 'ttl' => 3600],
            ],
        );

        $domain = Domain::factory()->create(['domain' => 'example.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);
        $context = CheckContextDTO::fromExecution($domain, $scan, ScanOptionsDTO::fromArray([]));

        $execution = app(SpfCheck::class)->run($context, $dns);

        $this->assertSame('spf', $execution->result->key);
        $this->assertArrayHasKey(ScanArtifactKeys::LEGACY_SPF_RAW, $execution->artifacts);
        $this->assertArrayHasKey(ScanArtifactKeys::NATIVE_SPF_RESULT, $execution->artifacts);
        $this->assertSame($spfPayload['record'], $execution->result->data['record'] ?? null);
    }

    public function test_native_missing_spf_state(): void
    {
        $dns = new DnsCollectionResultDTO(
            records: ['SPF' => ['status' => 'missing']],
            score: 0,
            scoreBreakdown: [],
            legacyDnsPayload: [],
            rootTxtRecords: [],
        );

        $domain = Domain::factory()->create(['domain' => 'missing.test']);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'user_id' => $domain->user_id]);
        $context = CheckContextDTO::fromExecution($domain, $scan, ScanOptionsDTO::fromArray([]));

        $execution = app(SpfCheck::class)->run($context, $dns);

        $this->assertSame('missing', $execution->result->status);
        $this->assertNull($execution->result->data['record'] ?? null);
    }
}
