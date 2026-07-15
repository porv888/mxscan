<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FakeMtaStsDnsResolver;
use Tests\Support\EmailSecurity\FakeMtaStsHttpClient;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class MtaStsNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_missing_mta_sts_indicator(): void
    {
        $execution = $this->runPipeline('mta-missing.test', null);
        $this->assertSame('none', $execution->resultJson['mta_sts']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mtaStsEarned($execution));
    }

    public function test_valid_enforce_policy_pipeline(): void
    {
        $policy = "version: STSv1\nmode: enforce\nmax_age: 604800\nmx: *.mail.example.com\n";
        $execution = $this->runPipeline('mta-enforce.test', 'v=STSv1; id=20260714;', $policy);
        $this->assertSame('valid', $execution->resultJson['mta_sts']['analysis']['protocol_status'] ?? null);
        $this->assertSame('enforce', $execution->resultJson['mta_sts']['analysis']['policy']['mode'] ?? null);
        $this->assertArrayHasKey('analysis', $execution->resultJson['mta_sts']);
    }

    private function runPipeline(string $domainName, ?string $indicator, ?string $policyBody = null)
    {
        config(['email-security.spf_engine' => 'legacy']);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $dnsResolver = new FakeMtaStsDnsResolver();
        $httpClient = new FakeMtaStsHttpClient();
        CertificateTestProbeFactory::bindFakeProbes();

        if ($indicator !== null) {
            $dnsResolver->setTxt('_mta-sts.' . $domainName, new \App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsQueryResult(
                hostname: '_mta-sts.' . $domainName,
                success: true,
                reconstructedTxt: [$indicator],
            ));
        }

        if ($policyBody !== null) {
            $httpClient->setResponse($domainName, new MtaStsPolicyFetchResult(
                url: MtaStsPolicyFetcher::policyUrl($domainName),
                status: MtaStsPolicyFetchResult::STATUS_SUCCESS,
                httpStatus: 200,
                contentType: 'text/plain',
                body: $policyBody,
            ));
        }

        $this->app->instance(MtaStsDnsResolverInterface::class, $dnsResolver);
        $this->app->instance(MtaStsHttpClientInterface::class, $httpClient);

        $dnsPayload = [
            'score' => 0,
            'records' => [
                'SPF' => ['status' => 'missing'],
                'DMARC' => ['status' => 'missing'],
                'TLS-RPT' => ['status' => 'missing'],
                'MTA-STS' => $indicator ? ['status' => 'found', 'data' => $indicator] : ['status' => 'missing'],
                'BIMI' => ['status' => 'missing'],
            ],
            'score_breakdown' => [],
            'root_txt_records' => [],
            'dmarc_txt_records' => [],
            'mta_sts_txt_records' => $indicator ? [[
                'host' => '_mta-sts.' . $domainName,
                'txt' => $indicator,
                'ttl' => 3600,
                'rr_index' => 0,
            ]] : [],
        ];
        $dnsPayload['records']['MX'] = ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mx1.mail.example.com']]];
        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindMxFixtures($dnsPayload, $domainName);

        $scanner = Mockery::mock(\App\Services\ScannerService::class);
        $scanner->shouldReceive('scanDomain')->andReturn($dnsPayload);
        $this->app->instance(\App\Services\ScannerService::class, $scanner);

        $domain = Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create(['domain_id' => $domain->id, 'status' => 'running']);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => false, 'blacklist' => false]),
            microtime(true),
        );
    }

    private function mtaStsEarned(object $execution): int
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        foreach ($breakdown as $row) {
            if (($row['key'] ?? '') === 'mtasts') {
                return (int) ($row['earned'] ?? 0);
            }
        }

        return -1;
    }
}
