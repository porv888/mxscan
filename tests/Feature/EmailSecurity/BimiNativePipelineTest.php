<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Bimi\BimiProtocolStatus;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStates;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FakeBimiDnsResolver;
use Tests\TestCase;

class BimiNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_missing_bimi_record(): void
    {
        $execution = $this->runPipeline('bimi-missing.test', null);
        $this->assertSame('none', $execution->resultJson['bimi']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->bimiEarned($execution));
    }

    public function test_explicit_declination(): void
    {
        $record = 'v=BIMI1; l=; a=;';
        $execution = $this->runPipeline('bimi-declined.test', $record);
        $this->assertSame(BimiProtocolStatus::DECLINED, $execution->resultJson['bimi']['analysis']['protocol_status'] ?? null);
        $this->assertSame(BimiStates::DECLINED, $execution->resultJson['bimi']['analysis']['state'] ?? null);
        $this->assertSame(0, $this->bimiEarned($execution));
    }

    public function test_multiple_bimi_records_permerror(): void
    {
        $execution = $this->runPipeline('bimi-multi.test', null, [
            'bimi_txt_records' => [
                ['host' => 'default._bimi.bimi-multi.test', 'txt' => 'v=BIMI1; l=https://a.test/l.svg;', 'ttl' => 3600, 'rr_index' => 0],
                ['host' => 'default._bimi.bimi-multi.test', 'txt' => 'v=BIMI1; l=https://b.test/l.svg;', 'ttl' => 3600, 'rr_index' => 1],
            ],
        ]);
        $this->assertSame('permerror', $execution->resultJson['bimi']['analysis']['protocol_status'] ?? null);
    }

    public function test_invalid_bimi_version(): void
    {
        $execution = $this->runPipeline('bimi-badver.test', 'v=BIMI10; l=https://example.test/logo.svg;');
        $this->assertSame('permerror', $execution->resultJson['bimi']['analysis']['protocol_status'] ?? null);
    }

    public function test_score_unchanged_with_bimi_zero_weight(): void
    {
        $execution = $this->runPipeline('bimi-score.test', 'v=BIMI1; l=; a=;');
        $total = (int) ($execution->resultJson['dns']['score'] ?? $execution->score ?? 0);
        $this->assertSame(0, $this->bimiEarned($execution));
        $this->assertSame(0, $this->bimiPossible($execution));
        $this->assertLessThanOrEqual(100, $total);
    }

    public function test_result_json_has_native_analysis_block(): void
    {
        $execution = $this->runPipeline('bimi-analysis.test', 'v=BIMI1; l=; a=;');
        $this->assertSame('bimi-native-v1', $execution->resultJson['bimi']['analysis']['version'] ?? null);
        $this->assertArrayHasKey('standards_profile', $execution->resultJson['bimi']['analysis'] ?? []);
    }

    public function test_valid_indicator_writes_preview_ref_and_cache(): void
    {
        \Illuminate\Support\Facades\Storage::fake('local');

        $domainName = 'bimi-preview-cache.test';
        $record = 'v=BIMI1; l=https://logo.example.test/brand.svg; a=;';
        $execution = $this->runPipeline($domainName, $record, httpBody: \Tests\Support\EmailSecurity\BimiTestFixtures::VALID_SVG);

        $analysis = $execution->resultJson['bimi']['analysis'] ?? [];
        $this->assertSame('valid', $analysis['indicator']['status'] ?? null);
        $this->assertArrayHasKey('preview_ref', $analysis['indicator'] ?? []);
        $sha256 = (string) ($analysis['indicator']['sha256'] ?? '');
        $scanId = (string) ($analysis['indicator']['preview_ref']['scan_id'] ?? '');
        $this->assertNotSame('', $sha256);
        $this->assertNotSame('', $scanId);
        $this->assertTrue(app(\App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore::class)->exists($scanId, $sha256));
        $this->assertArrayNotHasKey('_decompressed_svg', $analysis['indicator'] ?? []);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function runPipeline(string $domainName, ?string $record, array $options = [], ?string $httpBody = null)
    {
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $dnsResolver = new FakeBimiDnsResolver();
        if ($record !== null && !isset($options['bimi_txt_records'])) {
            $dnsResolver->setTxt('default._bimi.' . $domainName, new BimiDnsQueryResult(
                hostname: 'default._bimi.' . $domainName,
                success: true,
                reconstructedTxt: [$record],
            ));
        }
        $this->app->instance(BimiDnsResolverInterface::class, $dnsResolver);

        $httpClient = Mockery::mock(BimiHttpClientInterface::class);
        if ($httpBody !== null) {
            $httpClient->shouldReceive('fetch')->andReturn([
                'success' => true,
                'url' => 'https://logo.example.test/brand.svg',
                'http_status' => 200,
                'content_type' => 'image/svg+xml',
                'body' => $httpBody,
                'duration_ms' => 5,
                'tls_verified' => true,
                'error' => null,
                'failure_category' => null,
                'resolved_ips' => ['93.184.216.34'],
            ]);
        } else {
            $httpClient->shouldReceive('fetch')->andReturn([
                'success' => false,
                'url' => '',
                'http_status' => null,
                'content_type' => null,
                'body' => null,
                'duration_ms' => 0,
                'tls_verified' => false,
                'error' => 'not_requested',
                'failure_category' => 'not_requested',
                'resolved_ips' => [],
            ]);
        }
        $this->app->instance(BimiHttpClientInterface::class, $httpClient);

        $txtRecords = $options['bimi_txt_records'] ?? null;
        if ($txtRecords === null && $record !== null) {
            $txtRecords = [[
                'host' => 'default._bimi.' . $domainName,
                'txt' => $record,
                'ttl' => 3600,
                'rr_index' => 0,
            ]];
        }

        $scanner = Mockery::mock(\App\Services\ScannerService::class);
        $scanner->shouldReceive('scanDomain')->andReturn([
            'score' => 0,
            'records' => [
                'MX' => ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mx.example.test']]],
                'SPF' => ['status' => 'missing'],
                'DMARC' => ['status' => 'missing'],
                'TLS-RPT' => ['status' => 'missing'],
                'MTA-STS' => ['status' => 'missing'],
            ],
            'score_breakdown' => [],
            'root_txt_records' => [],
            'dmarc_txt_records' => [],
            'mta_sts_txt_records' => [],
            'tls_rpt_txt_records' => [],
            'bimi_txt_records' => $txtRecords ?? [],
        ]);
        $this->app->instance(\App\Services\ScannerService::class, $scanner);

        $domain = Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create(['domain_id' => $domain->id]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            new ScanOptionsDTO(dns: true, spf: false, blacklist: false, dkim: false),
            microtime(true),
        );
    }

    private function bimiEarned($execution): int
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $row = app(ScoreBreakdownService::class)->findRow($breakdown, 'bimi');

        return (int) ($row['earned'] ?? -1);
    }

    private function bimiPossible($execution): int
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $row = app(ScoreBreakdownService::class)->findRow($breakdown, 'bimi');

        return (int) ($row['possible'] ?? -1);
    }
}
