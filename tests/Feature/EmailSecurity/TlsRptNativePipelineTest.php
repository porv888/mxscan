<?php

namespace Tests\Feature\EmailSecurity;

use App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation\TlsRptDnsQueryResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScoreBreakdownService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\Support\EmailSecurity\FakeTlsRptDnsResolver;
use Tests\TestCase;

class TlsRptNativePipelineTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_missing_tls_rpt_policy(): void
    {
        $execution = $this->runPipeline('tls-missing.test', null);
        $this->assertSame('none', $execution->resultJson['tls_rpt']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->tlsRptEarned($execution));
    }

    public function test_valid_mailto_destination(): void
    {
        $record = 'v=TLSRPTv1; rua=mailto:tlsrpt@example.test';
        $execution = $this->runPipeline('tls-mailto.test', $record);
        $this->assertSame('valid', $execution->resultJson['tls_rpt']['analysis']['protocol_status'] ?? null);
        $this->assertSame(TlsRptStates::PASS, $execution->resultJson['tls_rpt']['analysis']['state'] ?? null);
        $this->assertSame(5, $this->tlsRptEarned($execution));
    }

    public function test_valid_https_destination(): void
    {
        $record = 'v=TLSRPTv1; rua=https://reports.example.test/tls';
        $execution = $this->runPipeline('tls-https.test', $record);
        $this->assertSame('valid', $execution->resultJson['tls_rpt']['analysis']['protocol_status'] ?? null);
        $this->assertSame(5, $this->tlsRptEarned($execution));
    }

    public function test_multiple_tls_rpt_records_permerror(): void
    {
        $execution = $this->runPipeline('tls-multi.test', null, [
            'tls_rpt_txt_records' => [
                ['host' => '_smtp._tls.tls-multi.test', 'txt' => 'v=TLSRPTv1; rua=mailto:a@example.test', 'ttl' => 3600, 'rr_index' => 0],
                ['host' => '_smtp._tls.tls-multi.test', 'txt' => 'v=TLSRPTv1; rua=mailto:b@example.test', 'ttl' => 3600, 'rr_index' => 1],
            ],
        ]);
        $this->assertSame('permerror', $execution->resultJson['tls_rpt']['analysis']['protocol_status'] ?? null);
        $this->assertSame(0, $this->tlsRptEarned($execution));
    }

    public function test_dns_timeout_scores_partial(): void
    {
        $dnsResolver = new FakeTlsRptDnsResolver();
        $hostname = '_smtp._tls.tls-timeout.test';
        $dnsResolver->setTxt($hostname, new TlsRptDnsQueryResult(
            hostname: $hostname,
            success: false,
            outcome: TlsRptDnsQueryResult::OUTCOME_TIMEOUT,
            error: 'timeout',
        ));
        $this->app->instance(TlsRptDnsResolverInterface::class, $dnsResolver);

        $execution = $this->runPipeline('tls-timeout.test', null, ['use_resolver_only' => true]);
        $this->assertSame(TlsRptProtocolStatus::TEMPERROR, $execution->resultJson['tls_rpt']['analysis']['protocol_status'] ?? null);
        $this->assertSame(2, $this->tlsRptEarned($execution));
    }

    /**
     * @param array<string, mixed> $options
     */
    private function runPipeline(string $domainName, ?string $record, array $options = [])
    {
        $this->app->forgetInstance(\App\Domain\EmailSecurity\Checks\CheckRegistry::class);

        $useResolverOnly = (bool) ($options['use_resolver_only'] ?? false);
        $txtRecords = $options['tls_rpt_txt_records'] ?? null;

        if (!$useResolverOnly && $txtRecords === null) {
            $dnsResolver = new FakeTlsRptDnsResolver();
            if ($record !== null) {
                $dnsResolver->setTxt('_smtp._tls.' . $domainName, new TlsRptDnsQueryResult(
                    hostname: '_smtp._tls.' . $domainName,
                    success: true,
                    reconstructedTxt: [$record],
                ));
            }
            $this->app->instance(TlsRptDnsResolverInterface::class, $dnsResolver);
        }

        if ($txtRecords === null && !$useResolverOnly && $record !== null) {
            $txtRecords = [[
                'host' => '_smtp._tls.' . $domainName,
                'txt' => $record,
                'ttl' => 3600,
                'rr_index' => 0,
            ]];
        }

        if ($useResolverOnly) {
            $txtRecords = [];
        }

        $scanner = Mockery::mock(\App\Services\ScannerService::class);
        $scanner->shouldReceive('scanDomain')->andReturn([
            'score' => 0,
            'records' => [
                'MX' => ['status' => 'found', 'data' => [['pri' => 10, 'target' => 'mx.example.test']]],
                'SPF' => ['status' => 'missing'],
                'DMARC' => ['status' => 'missing'],
                'TLS-RPT' => $record && !$useResolverOnly ? ['status' => 'found', 'data' => $record] : ['status' => 'missing'],
                'MTA-STS' => ['status' => 'missing'],
                'BIMI' => ['status' => 'missing'],
            ],
            'score_breakdown' => [],
            'root_txt_records' => [],
            'dmarc_txt_records' => [],
            'mta_sts_txt_records' => [],
            'tls_rpt_txt_records' => $txtRecords ?? [],
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

    private function tlsRptEarned($execution): int
    {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        $row = app(ScoreBreakdownService::class)->findRow($breakdown, 'tlsrpt');

        return (int) ($row['earned'] ?? -1);
    }
}
