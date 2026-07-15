<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;
use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Reporting\ScanResultNormalizer;
use App\Jobs\RunFullScan;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScanRunner;
use App\Services\ScoreBreakdownService;
use App\Services\Spf\DTOs\SpfResultDTO;
use App\Services\Spf\SpfResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\CertificateTestProbeFactory;
use Tests\Support\EmailSecurity\FakeMtaStsDnsResolver;
use Tests\Support\EmailSecurity\FakeMtaStsHttpClient;
use Tests\Support\EmailSecurity\FakeMxDnsResolver;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\MxFixtureBuilder;
use Tests\TestCase;

class MxNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    private ScoreBreakdownService $scoreBreakdown;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);
        $this->scoreBreakdown = new ScoreBreakdownService();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_one_healthy_mx(): void
    {
        $domain = 'mx-one.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);

        $this->assertAnalysisContract($execution);
        $this->assertSame(MxProtocolStatus::VALID, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(MxServiceMode::ACCEPTS_MAIL, $execution->resultJson['mx']['analysis']['service_mode'] ?? null);
        $this->assertSame(15, $this->mxEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_multiple_healthy_mx_hosts(): void
    {
        $domain = 'mx-multi.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
            MxFixtureBuilder::mxRow(20, 'mx2.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['8.8.8.8']);
            $resolver->setA('mx2.' . $domain, ['1.1.1.1']);
        });

        $this->assertSame(2, $execution->resultJson['mx']['analysis']['usable_targets'] ?? 0);
        $this->assertSame(15, $this->mxEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_equal_mx_preferences(): void
    {
        $domain = 'mx-equal.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
            MxFixtureBuilder::mxRow(10, 'mx2.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['8.8.8.8']);
            $resolver->setA('mx2.' . $domain, ['1.1.1.1']);
        });

        $this->assertSame(2, $execution->resultJson['mx']['analysis']['usable_targets'] ?? 0);
        $this->assertSame(15, $this->mxEarned($execution));
    }

    public function test_single_healthy_mx_host(): void
    {
        $domain = 'mx-single.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(5, 'mail.' . $domain),
        ]);

        $targets = $execution->resultJson['mx']['analysis']['targets'] ?? [];
        $this->assertCount(1, $targets);
        $this->assertSame(MxTargetResolver::STATUS_USABLE, $targets[0]['status'] ?? null);
        $this->assertSame(15, $this->mxEarned($execution));
    }

    public function test_valid_null_mx(): void
    {
        $domain = 'mx-null.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(0, '.'),
        ]);

        $this->assertTrue($execution->resultJson['mx']['analysis']['null_mx']['valid'] ?? false);
        $this->assertSame(MxServiceMode::NO_INBOUND_MAIL, $execution->resultJson['mx']['analysis']['service_mode'] ?? null);
        $this->assertSame(15, $this->mxEarned($execution));
        $this->assertRecommendationKeysUnique($execution);
    }

    public function test_null_mx_mixed_with_ordinary_mx(): void
    {
        $domain = 'mx-null-mixed.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(0, '.'),
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);

        $this->assertSame(MxProtocolStatus::PERMERROR, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
        $this->assertRecommendationContains($execution, 'fix_invalid_null_mx');
    }

    public function test_malformed_null_mx(): void
    {
        $domain = 'mx-null-bad.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, '.'),
        ]);

        $this->assertFalse($execution->resultJson['mx']['analysis']['null_mx']['valid'] ?? true);
        $this->assertSame(MxProtocolStatus::PERMERROR, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_no_mx_with_usable_ipv4_implicit_fallback(): void
    {
        $domain = 'mx-implicit-v4.test';
        $resolver = new FakeMxDnsResolver();
        $resolver->setMx($domain, []);
        $resolver->setA($domain, ['8.8.8.8']);
        $execution = $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, null));

        $this->assertTrue($execution->resultJson['mx']['analysis']['implicit_fallback']['active'] ?? false);
        $this->assertSame(MxServiceMode::IMPLICIT_DELIVERY, $execution->resultJson['mx']['analysis']['service_mode'] ?? null);
        $this->assertSame(10, $this->mxEarned($execution));
        $this->assertRecommendationContains($execution, 'review_implicit_mx_fallback');
    }

    public function test_no_mx_with_usable_ipv6_implicit_fallback(): void
    {
        $domain = 'mx-implicit-v6.test';
        $resolver = new FakeMxDnsResolver();
        $resolver->setMx($domain, []);
        $resolver->setAaaa($domain, ['2001:4860:4860::8888']);
        $execution = $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, null));

        $this->assertTrue($execution->resultJson['mx']['analysis']['implicit_fallback']['active'] ?? false);
        $this->assertSame(MxServiceMode::IMPLICIT_DELIVERY, $execution->resultJson['mx']['analysis']['service_mode'] ?? null);
        $this->assertSame(10, $this->mxEarned($execution));
    }

    public function test_no_mx_and_no_a_aaaa(): void
    {
        $domain = 'mx-absent.test';
        $resolver = new FakeMxDnsResolver();
        $resolver->setMx($domain, []);
        $execution = $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, null));

        $this->assertSame(MxProtocolStatus::NONE, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
        $this->assertRecommendationContains($execution, 'add_mx');
    }

    public function test_explicit_mx_with_all_targets_dangling(): void
    {
        $domain = 'mx-dangling.test';
        $resolver = new FakeMxDnsResolver();
        $resolver->setMx($domain, [MxFixtureBuilder::mxRow(10, 'mx1.' . $domain)]);
        $execution = $this->runPipeline(
            $domain,
            $resolver,
            MxFixtureBuilder::dnsPayload($domain, [MxFixtureBuilder::mxRow(10, 'mx1.' . $domain)]),
        );

        $this->assertSame(0, $execution->resultJson['mx']['analysis']['usable_targets'] ?? -1);
        $this->assertSame(MxTargetResolver::STATUS_DANGLING, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_one_healthy_and_one_dangling_target(): void
    {
        $domain = 'mx-partial.test';
        $mxRecords = [
            MxFixtureBuilder::mxRow(10, 'good.' . $domain),
            MxFixtureBuilder::mxRow(20, 'bad.' . $domain),
        ];
        $resolver = new FakeMxDnsResolver();
        $resolver->setMx($domain, $mxRecords);
        $resolver->setA('good.' . $domain, ['8.8.8.8']);
        $execution = $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, $mxRecords));

        $this->assertSame(1, $execution->resultJson['mx']['analysis']['usable_targets'] ?? 0);
        $this->assertSame(1, $execution->resultJson['mx']['analysis']['invalid_targets'] ?? 0);
        $this->assertSame(12, $this->mxEarned($execution));
    }

    public function test_mx_target_is_cname(): void
    {
        $domain = 'mx-cname.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setCname('mx1.' . $domain, 'mail.' . $domain);
        });

        $this->assertSame(MxTargetResolver::STATUS_ALIAS_INVALID, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_cname_cycle(): void
    {
        $domain = 'mx-cycle.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setCname('mx1.' . $domain, 'mx2.' . $domain);
            $resolver->setCname('mx2.' . $domain, 'mx1.' . $domain);
        });

        $target = $execution->resultJson['mx']['analysis']['targets'][0] ?? [];
        $this->assertSame(MxTargetResolver::STATUS_ALIAS_INVALID, $target['status'] ?? null);
        $this->assertTrue($target['is_alias'] ?? false);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_mx_target_resolves_only_to_private_ip(): void
    {
        $domain = 'mx-private.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['10.0.0.5']);
        });

        $this->assertSame(MxTargetResolver::STATUS_NON_PUBLIC_ONLY, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_mx_target_resolves_only_to_reserved_documentation_ip(): void
    {
        $domain = 'mx-doc.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['192.0.2.10']);
        });

        $this->assertSame(MxTargetResolver::STATUS_NON_PUBLIC_ONLY, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_mx_target_has_one_public_and_one_invalid_address(): void
    {
        $domain = 'mx-mixed-addr.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['8.8.8.8', '10.0.0.1']);
        });

        $this->assertSame(MxTargetResolver::STATUS_USABLE_WITH_WARNINGS, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(12, $this->mxEarned($execution));
    }

    public function test_invalid_mx_hostname(): void
    {
        $domain = 'mx-bad-host.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'not_valid!!'),
        ]);

        $this->assertSame(MxProtocolStatus::PERMERROR, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_ip_literal_used_as_mx_exchange(): void
    {
        $domain = 'mx-ip-literal.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, '192.0.2.1'),
        ]);

        $this->assertSame(MxProtocolStatus::PERMERROR, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->mxEarned($execution));
    }

    public function test_duplicate_identical_mx_records(): void
    {
        $domain = 'mx-dup.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);

        $warnings = $execution->resultJson['mx']['analysis']['warnings'] ?? [];
        $this->assertNotEmpty(array_filter($warnings, fn (array $w) => ($w['code'] ?? '') === 'DUPLICATE_MX_RECORD'));
        $this->assertSame(15, $this->mxEarned($execution));
    }

    public function test_repeated_hostname_with_conflicting_preferences(): void
    {
        $domain = 'mx-conflict.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
            MxFixtureBuilder::mxRow(20, 'mx1.' . $domain),
        ]);

        $warnings = $execution->resultJson['mx']['analysis']['warnings'] ?? [];
        $this->assertNotEmpty($warnings);
        $this->assertSame(15, $this->mxEarned($execution));
    }

    public function test_mx_dns_timeout(): void
    {
        $domain = 'mx-timeout.test';
        $resolver = new FakeMxDnsResolver();
        $resolver->setResponse('MX:' . $domain, new MxDnsQueryResult(
            hostname: $domain,
            success: false,
            error: 'timeout',
            outcome: MxDnsQueryResult::OUTCOME_TIMEOUT,
        ));
        $execution = $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, null));

        $this->assertSame(MxProtocolStatus::TEMPERROR, $execution->resultJson['mx']['analysis']['protocol_status'] ?? null);
        $this->assertSame(5, $this->mxEarned($execution));
        $this->assertRecommendationContains($execution, 'investigate_mx_dns_failure');
    }

    public function test_target_a_timeout(): void
    {
        $domain = 'mx-target-timeout.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setResponse('A:mx1.' . $domain, new MxDnsQueryResult(
                hostname: 'mx1.' . $domain,
                success: false,
                error: 'timeout',
                outcome: MxDnsQueryResult::OUTCOME_TIMEOUT,
            ));
            $resolver->setResponse('AAAA:mx1.' . $domain, new MxDnsQueryResult(
                hostname: 'mx1.' . $domain,
                success: false,
                error: 'timeout',
                outcome: MxDnsQueryResult::OUTCOME_TIMEOUT,
            ));
        });

        $this->assertSame(MxTargetResolver::STATUS_TEMPORARY_DNS_FAILURE, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
    }

    public function test_target_aaaa_servfail_with_usable_a(): void
    {
        $domain = 'mx-aaaa-servfail.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], function (FakeMxDnsResolver $resolver) use ($domain): void {
            $resolver->setA('mx1.' . $domain, ['8.8.8.8']);
            $resolver->setResponse('AAAA:mx1.' . $domain, new MxDnsQueryResult(
                hostname: 'mx1.' . $domain,
                success: false,
                error: 'servfail',
                outcome: MxDnsQueryResult::OUTCOME_SERVFAIL,
            ));
        });

        $this->assertSame(MxTargetResolver::STATUS_PARTIALLY_RESOLVED, $execution->resultJson['mx']['analysis']['targets'][0]['status'] ?? null);
        $this->assertSame(12, $this->mxEarned($execution));
    }

    public function test_mx_only_scan(): void
    {
        $domain = 'mx-only.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ], null, ['dns' => true, 'spf' => false, 'blacklist' => false]);

        $this->assertArrayHasKey('mx', $execution->resultJson);
        $this->assertArrayNotHasKey('spf', $execution->resultJson);
        $this->assertSame(15, $this->mxEarned($execution));
        $this->assertScoreInvariant($execution);
    }

    public function test_full_scan_with_all_protocols(): void
    {
        $domain = 'mx-full.test';
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $dnsPayload['records']['MX'] = [
            'status' => 'found',
            'data' => [['pri' => 10, 'target' => 'mail.' . $domain, 'ttl' => 3600]],
        ];
        $spfPayload = FixtureLoader::input('spf-configured');

        FixtureLoader::bindDnsCollector($dnsPayload);
        FixtureLoader::bindDkimResolver($domain);
        FixtureLoader::bindMtaStsFixtures();
        FixtureLoader::bindTlsRptFixtures();
        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, [
            MxFixtureBuilder::mxRow(10, 'mail.' . $domain),
        ]);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $spfResolver = Mockery::mock(SpfResolver::class);
        $spfResolver->shouldReceive('resolve')->andReturn(new SpfResultDTO(
            currentRecord: $spfPayload['record'],
            lookupsUsed: $spfPayload['lookups'],
            flattenedSpf: $spfPayload['flattened'],
            warnings: [],
            resolvedIps: [],
        ));
        $this->app->instance(SpfResolver::class, $spfResolver);

        $modelDomain = Domain::factory()->create(['domain' => $domain]);
        $scan = Scan::factory()->create(['domain_id' => $modelDomain->id, 'user_id' => $modelDomain->user_id, 'status' => 'running']);
        $execution = app(EmailSecurityScanService::class)->execute(
            $modelDomain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => true, 'blacklist' => true]),
            microtime(true),
        );

        $this->assertArrayHasKey('mx', $execution->resultJson);
        $this->assertArrayHasKey('spf', $execution->resultJson);
        $this->assertArrayHasKey('dmarc', $execution->resultJson);
        $this->assertArrayHasKey('dkim', $execution->resultJson);
        $this->assertArrayHasKey('mta_sts', $execution->resultJson);
        $this->assertArrayHasKey('tls_rpt', $execution->resultJson);
        $this->assertScoreInvariant($execution);
    }

    public function test_mta_sts_consumes_native_mx_evidence(): void
    {
        $domain = 'mx-mta-sts.test';
        $mxHost = 'mx1.' . $domain;
        $indicator = 'v=STSv1; id=20240101T000000;';
        $policyBody = "version: STSv1\nmode: testing\nmax_age: 604800\nmx: {$mxHost}\n";

        $dnsPayload = MxFixtureBuilder::dnsPayload($domain, [
            MxFixtureBuilder::mxRow(10, $mxHost),
        ]);
        $dnsPayload['records']['MTA-STS'] = ['status' => 'found', 'data' => $indicator];
        $dnsPayload['mta_sts_txt_records'] = [[
            'host' => '_mta-sts.' . $domain,
            'txt' => $indicator,
            'ttl' => 3600,
            'rr_index' => 0,
        ]];

        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, [
            MxFixtureBuilder::mxRow(10, $mxHost),
        ]);

        $mtaDns = new FakeMtaStsDnsResolver();
        $mtaDns->setTxt('_mta-sts.' . $domain, new \App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsQueryResult(
            hostname: '_mta-sts.' . $domain,
            success: true,
            reconstructedTxt: [$indicator],
        ));
        $httpClient = new FakeMtaStsHttpClient();
        $httpClient->setResponse($domain, new MtaStsPolicyFetchResult(
            url: MtaStsPolicyFetcher::policyUrl($domain),
            status: MtaStsPolicyFetchResult::STATUS_SUCCESS,
            httpStatus: 200,
            contentType: 'text/plain',
            body: $policyBody,
        ));

        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->instance(MtaStsDnsResolverInterface::class, $mtaDns);
        $this->app->instance(MtaStsHttpClientInterface::class, $httpClient);
        CertificateTestProbeFactory::bindFakeProbes();
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $modelDomain = Domain::factory()->create(['domain' => $domain]);
        $scan = Scan::factory()->create(['domain_id' => $modelDomain->id, 'user_id' => $modelDomain->user_id, 'status' => 'running']);
        $execution = app(EmailSecurityScanService::class)->execute(
            $modelDomain,
            $scan,
            ScanOptionsDTO::fromArray(['dns' => true, 'spf' => false, 'blacklist' => false]),
            microtime(true),
        );

        $mxHosts = array_column($execution->resultJson['mx']['analysis']['targets'] ?? [], 'normalized_hostname');
        $mtaHosts = array_column($execution->resultJson['mta_sts']['analysis']['mx_validation'] ?? [], 'hostname');
        $this->assertNotEmpty($mxHosts);
        $this->assertSame($mxHosts, $mtaHosts);
    }

    public function test_public_scan_entry(): void
    {
        $domain = 'mx-public.test';
        $dnsPayload = MxFixtureBuilder::dnsPayload($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $response = $this->post(route('public.scan.run'), ['domain' => $domain]);

        $response->assertOk();
        $response->assertViewHas('results', function (array $results): bool {
            return ($results['mx']['analysis']['version'] ?? null) === 'mx-native-v1';
        });
    }

    public function test_queued_run_full_scan_entry(): void
    {
        $domain = 'mx-queued.test';
        $dnsPayload = MxFixtureBuilder::dnsPayload($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $modelDomain = Domain::factory()->create(['domain' => $domain]);
        $job = new RunFullScan($modelDomain->id, [
            'dns' => true,
            'spf' => false,
            'blacklist' => false,
            'monitoring' => false,
        ]);
        $job->handle(
            app(EmailSecurityScanService::class),
            app(\App\Domain\EmailSecurity\Contracts\ScanPersisterInterface::class),
            app(\App\Services\ScanReport\ScanFinalizer::class),
        );

        $scan = Scan::query()->where('domain_id', $modelDomain->id)->latest('id')->first();
        $this->assertNotNull($scan);
        $facts = is_array($scan->facts_json) ? $scan->facts_json : [];
        $this->assertArrayHasKey('mx_protocol_status', $facts);
        $this->assertArrayHasKey('mx_service_mode', $facts);
        $this->assertSame('mx-native-v1', $scan->result_json['mx']['analysis']['version'] ?? null);
    }

    public function test_scheduled_scan_runner_entry(): void
    {
        $domain = 'mx-scheduled.test';
        $dnsPayload = MxFixtureBuilder::dnsPayload($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $modelDomain = Domain::factory()->create(['domain' => $domain]);
        $scan = app(ScanRunner::class)->runSync($modelDomain, [
            'dns' => true,
            'spf' => false,
            'blacklist' => false,
            'monitoring' => false,
        ]);
        $scan->refresh();

        $this->assertSame('mx-native-v1', $scan->result_json['mx']['analysis']['version'] ?? null);
        $this->assertSame(MxStates::PASS, $scan->result_json['mx']['analysis']['state'] ?? null);
    }

    public function test_historical_scan_reload(): void
    {
        $domain = 'mx-history.test';
        $execution = $this->runWithMx($domain, [
            MxFixtureBuilder::mxRow(10, 'mx1.' . $domain),
        ]);

        $normalizer = new ScanResultNormalizer();
        $assembler = new ScanResultAssembler();
        $normalized = $normalizer->normalize(new ScanResultDTO($execution->resultJson));
        $roundTrip = $assembler->toScanResultDTO($normalized);

        $this->assertSame(
            'mx-native-v1',
            $roundTrip->toArray()['mx']['analysis']['version'] ?? null,
        );

        $analysis = MxAnalysisReader::analysis($execution->resultJson['mx'] ?? null);
        $this->assertSame(MxStates::PASS, $analysis['state'] ?? null);
        $this->assertSame(MxServiceMode::ACCEPTS_MAIL, MxAnalysisReader::serviceMode($execution->resultJson['mx'] ?? null));

        $card = (new ScanReportStatusMapper())->mapMx(
            $execution->resultJson['dns']['records']['MX'] ?? null,
            $execution->resultJson['mx'] ?? null,
        );
        $this->assertNotSame(ScanReportStatusMapper::UNKNOWN, $card['state'] ?? ScanReportStatusMapper::UNKNOWN);

        $facts = ScanPayloadBuilder::buildFactsForSyncRunner($execution->resultJson);
        $this->assertArrayHasKey('mx_protocol_status', $facts);
        $this->assertArrayHasKey('mx_usable_target_count', $facts);
    }

    /**
     * @param list<array{pri: int, target: string}> $mxRecords
     * @param callable(FakeMxDnsResolver): void|null $configure
     * @param array<string, bool> $options
     */
    private function runWithMx(
        string $domain,
        array $mxRecords,
        ?callable $configure = null,
        array $options = ['dns' => true, 'spf' => false, 'blacklist' => false],
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        $resolver = new FakeMxDnsResolver();
        MxFixtureBuilder::bindHealthyTargets($resolver, $domain, $mxRecords);
        if ($configure !== null) {
            $configure($resolver);
        }

        return $this->runPipeline($domain, $resolver, MxFixtureBuilder::dnsPayload($domain, $mxRecords), $options);
    }

    /**
     * @param array<string, bool> $options
     */
    private function runPipeline(
        string $domainName,
        FakeMxDnsResolver $resolver,
        array $dnsPayload,
        array $options = ['dns' => true, 'spf' => false, 'blacklist' => false],
    ): \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO {
        FixtureLoader::bindDnsCollector($dnsPayload);
        $this->app->instance(MxDnsResolverInterface::class, $resolver);
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $domain = Domain::factory()->create(['domain' => $domainName]);
        $scan = Scan::factory()->create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'status' => 'running',
        ]);

        return app(EmailSecurityScanService::class)->execute(
            $domain,
            $scan,
            ScanOptionsDTO::fromArray($options),
            microtime(true),
        );
    }

    private function mxEarned(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): int
    {
        $row = $this->scoreBreakdown->findRow(
            $execution->resultJson['dns']['score_breakdown'] ?? [],
            'mx',
        );

        return (int) ($row['earned'] ?? -1);
    }

    private function assertScoreInvariant(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): void
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $sum = $this->scoreBreakdown->totalEarned($breakdown);
        $this->assertSame($execution->score, $sum);
        $this->assertSame($execution->score, $execution->resultJson['dns']['score'] ?? null);
    }

    private function assertAnalysisContract(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): void
    {
        $analysis = $execution->resultJson['mx']['analysis'] ?? [];
        $this->assertSame('mx-native-v1', $analysis['version'] ?? null);
        $this->assertArrayHasKey('protocol_status', $analysis);
        $this->assertArrayHasKey('service_mode', $analysis);
        $this->assertArrayHasKey('targets', $analysis);
        $this->assertArrayHasKey('null_mx', $analysis);
        $this->assertArrayHasKey('implicit_fallback', $analysis);
    }

    private function assertRecommendationContains(
        \App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution,
        string $semanticKey,
    ): void {
        $keys = array_column($execution->recommendations, 'semantic_key');
        if ($keys === []) {
            $keys = array_column($execution->recommendations, 'key');
        }
        $this->assertContains($semanticKey, $keys);
    }

    private function assertRecommendationKeysUnique(\App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO $execution): void
    {
        $keys = array_column($execution->recommendations, 'semantic_key');
        if ($keys === []) {
            $keys = array_column($execution->recommendations, 'key');
        }
        $this->assertSame(count($keys), count(array_unique($keys)));
    }
}
