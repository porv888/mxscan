<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;
use App\Domain\EmailSecurity\Scoring\LegacyDnsScoreCalculator;
use App\Domain\EmailSecurity\Scoring\Rules\DmarcScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\SpfScoreRule;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantGuard;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Support\ScoringInputFactory;
use App\Services\ScoreBreakdownService;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class EmailSecurityArchitectureTest extends TestCase
{
    public function test_scan_payload_builder_spf_status_for_high_lookups(): void
    {
        $dto = new \App\Services\Spf\DTOs\SpfResultDTO(
            currentRecord: 'v=spf1 include:example.com -all',
            lookupsUsed: 10,
            flattenedSpf: null,
            warnings: [],
            resolvedIps: [],
        );

        $payload = ScanPayloadBuilder::buildSpfResultPayload($dto);

        $this->assertSame('error', $payload['status']);
        $this->assertSame(10, $payload['lookups']);
    }

    public function test_legacy_score_calculator_preserves_scanner_total_with_scoring_input_dto(): void
    {
        $scoreBreakdownService = new ScoreBreakdownService();
        $calculator = new LegacyDnsScoreCalculator(
            $scoreBreakdownService,
            new SpfScoreRule(),
            new DmarcScoreRule(),
            new \App\Domain\EmailSecurity\Scoring\Rules\DkimScoreRule(),
            new \App\Domain\EmailSecurity\Scoring\Rules\MtaStsScoreRule(),
            new \App\Domain\EmailSecurity\Scoring\Rules\TlsRptScoreRule(),
            new \App\Domain\EmailSecurity\Scoring\Rules\MxScoreRule(),
            new \App\Domain\EmailSecurity\Checks\Certificates\Scoring\CertificateScoreRule(),
            new \App\Domain\EmailSecurity\Checks\Bimi\Scoring\BimiScoreRule(),
            new ScoreInvariantGuard($scoreBreakdownService),
        );
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $normalized = new NormalizedScanResultDTO(
            domain: 'example.test',
            collectedAt: now()->toIso8601String(),
            checkResults: [],
            legacyDnsMetadata: [
                'score' => $dnsPayload['score'],
                'score_breakdown' => $dnsPayload['score_breakdown'],
                'records' => $dnsPayload['records'],
                'legacy_payload' => $dnsPayload,
            ],
        );

        $input = new ScoringInputDTO(
            normalized: $normalized,
            scoreBreakdown: $dnsPayload['score_breakdown'],
        );

        $result = $calculator->calculate($input);

        $this->assertSame(64, $result->total);
        $this->assertCount(5, $result->breakdown);
    }

    public function test_determine_scan_type_for_single_blacklist_scan(): void
    {
        $type = ScanPayloadBuilder::determineScanType([
            'dns' => false,
            'spf' => false,
            'blacklist' => true,
        ]);

        $this->assertSame('blacklist', $type);
    }

    public function test_deprecated_mapper_alias_resolves(): void
    {
        $legacy = new \App\Services\ScanReport\ScanReportStatusMapper();
        $modern = new \App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper();

        $this->assertInstanceOf(\App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper::class, $legacy);
        $this->assertSame(
            $modern->mapDmarc(['status' => 'found', 'data' => 'v=DMARC1; p=reject']),
            $legacy->mapDmarc(['status' => 'found', 'data' => 'v=DMARC1; p=reject'])
        );
    }

    public function test_compatibility_shim_files_are_not_empty_self_extensions(): void
    {
        foreach ([
            app_path('Services/ScanReport/ScanRecommendationService.php'),
            app_path('Services/ScanReport/ScanReportStatusMapper.php'),
        ] as $path) {
            $contents = (string) file_get_contents($path);
            $this->assertStringContainsString('extends', $contents);
            $this->assertStringNotContainsString('extends \\' . basename($path, '.php'), $contents);
            $this->assertGreaterThan(100, strlen($contents));
        }
    }

    public function test_email_security_scan_service_is_transient_binding(): void
    {
        $first = app(\App\Services\EmailSecurityScanService::class);
        $second = app(\App\Services\EmailSecurityScanService::class);

        $this->assertNotSame($first, $second);
    }

    public function test_scan_result_assembler_projects_legacy_dns_payload_unchanged(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $assembler = new ScanResultAssembler();
        $normalized = new NormalizedScanResultDTO(
            domain: 'example.test',
            collectedAt: now()->toIso8601String(),
            checkResults: [],
            legacyDnsMetadata: [
                'legacy_payload' => $dnsPayload,
            ],
        );

        $result = $assembler->toScanResultDTO($normalized);

        $this->assertSame($dnsPayload, $result->toArray()['dns']);
    }
}
