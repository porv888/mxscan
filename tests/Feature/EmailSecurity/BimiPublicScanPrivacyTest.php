<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\BimiTestFixtures;
use Tests\Support\EmailSecurity\FakeBimiDnsResolver;
use Tests\TestCase;

class BimiPublicScanPrivacyTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_public_scan_shows_bimi_metadata_without_sensitive_fields(): void
    {
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $domainName = 'public-bimi.test';
        $record = 'v=BIMI1; l=https://logo.public-bimi.test/brand.svg; a=;';

        $dnsResolver = new FakeBimiDnsResolver();
        $dnsResolver->setTxt('default._bimi.' . $domainName, new BimiDnsQueryResult(
            hostname: 'default._bimi.' . $domainName,
            success: true,
            reconstructedTxt: [$record],
        ));
        $this->app->instance(BimiDnsResolverInterface::class, $dnsResolver);

        $httpClient = Mockery::mock(BimiHttpClientInterface::class);
        $httpClient->shouldReceive('fetch')->andReturn([
            'success' => true,
            'url' => 'https://logo.public-bimi.test/brand.svg',
            'http_status' => 200,
            'content_type' => 'image/svg+xml',
            'body' => BimiTestFixtures::VALID_SVG,
            'duration_ms' => 5,
            'tls_verified' => true,
            'error' => null,
            'failure_category' => null,
            'resolved_ips' => ['93.184.216.34'],
        ]);
        $this->app->instance(BimiHttpClientInterface::class, $httpClient);

        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: 'v=spf1 -all',
            lookupsUsed: 1,
            flattenedSpf: 'v=spf1 -all',
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);

        $scanner = Mockery::mock(\App\Services\ScannerService::class);
        $scanner->shouldReceive('scanDomain')->andReturn([
            'score' => 0,
            'records' => [
                'MX' => ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mx.example.test']]],
                'SPF' => ['status' => 'found', 'data' => 'v=spf1 -all'],
                'DMARC' => ['status' => 'missing'],
                'TLS-RPT' => ['status' => 'missing'],
                'MTA-STS' => ['status' => 'missing'],
            ],
            'score_breakdown' => [],
            'root_txt_records' => [],
            'dmarc_txt_records' => [],
            'mta_sts_txt_records' => [],
            'tls_rpt_txt_records' => [],
            'bimi_txt_records' => [[
                'host' => 'default._bimi.' . $domainName,
                'txt' => $record,
                'ttl' => 3600,
                'rr_index' => 0,
            ]],
        ]);
        $this->app->instance(\App\Services\ScannerService::class, $scanner);

        $response = $this->post(route('public.scan.run'), ['domain' => $domainName]);

        $response->assertOk();
        $response->assertSee('BIMI Readiness', false);
        $response->assertSee('default._bimi.' . $domainName, false);
        $html = $response->getContent();
        $this->assertStringNotContainsString('logo.public-bimi.test', $html);
        $this->assertStringNotContainsString(BimiTestFixtures::validSvgSha256(), $html);
        $this->assertStringNotContainsString('<img src="http', $html);
    }
}
