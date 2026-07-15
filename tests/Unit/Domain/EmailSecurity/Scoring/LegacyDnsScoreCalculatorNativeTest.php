<?php

namespace Tests\Unit\Domain\EmailSecurity\Scoring;

use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;
use App\Domain\EmailSecurity\Scoring\LegacyDnsScoreCalculator;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck;
use App\Domain\EmailSecurity\Scoring\Rules\DmarcScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\SpfScoreRule;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantGuard;
use App\Services\ScoreBreakdownService;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\Support\EmailSecurity\SpfNativeResultFactory;
use Tests\TestCase;

class LegacyDnsScoreCalculatorNativeTest extends TestCase
{
    public function test_dns_payload_without_native_spf_preserves_scanner_total(): void
    {
        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $calculator = $this->calculator();
        $input = $this->input($dnsPayload);

        $result = $calculator->calculate($input);

        $this->assertSame(64, $result->total);
    }

    public function test_native_branch_replaces_spf_earned_and_recomputes_total(): void
    {

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $native = SpfNativeResultFactory::make(
            lookupCount: 8,
            riskStatus: SpfRiskStatus::WARNING,
            state: SpfStates::WARNING,
            summary: 'SPF configuration valid; elevated lookup count (8/10).',
        );

        $calculator = $this->calculator();
        $input = new ScoringInputDTO(
            normalized: $this->normalized($dnsPayload),
            scoreBreakdown: $dnsPayload['score_breakdown'],
            scoreModelVersion: 'spf-v2',
            nativeSpfResult: $native,
        );

        $result = $calculator->calculate($input);
        $spfRow = (new ScoreBreakdownService())->findRow($result->breakdown, 'spf');

        $this->assertSame(18, $spfRow['earned'] ?? null);
        $this->assertSame(62, $result->total);
        $this->assertSame($result->total, (new ScoreBreakdownService())->totalEarned($result->breakdown));
    }

    public function test_native_branch_scores_missing_spf_as_zero(): void
    {

        $dnsPayload = FixtureLoader::input('dns-bundled-full');
        $native = SpfNativeResultFactory::make(
            protocolStatus: SpfProtocolStatus::NONE,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::MISSING,
            summary: 'SPF record missing.',
            rawRecord: null,
            terminalPolicy: SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            parsedTerminalPolicy: null,
        );

        $calculator = $this->calculator();
        $input = new ScoringInputDTO(
            normalized: $this->normalized($dnsPayload),
            scoreBreakdown: $dnsPayload['score_breakdown'],
            scoreModelVersion: 'spf-v2',
            nativeSpfResult: $native,
        );

        $result = $calculator->calculate($input);

        $this->assertSame(44, $result->total);
        $this->assertSame(0, (new ScoreBreakdownService())->findRow($result->breakdown, 'spf')['earned'] ?? null);
    }

    private function calculator(): LegacyDnsScoreCalculator
    {
        $scoreBreakdownService = new ScoreBreakdownService();

        return new LegacyDnsScoreCalculator(
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
    }

    /**
     * @param array<string, mixed> $dnsPayload
     */
    private function input(array $dnsPayload): ScoringInputDTO
    {
        return new ScoringInputDTO(
            normalized: $this->normalized($dnsPayload),
            scoreBreakdown: $dnsPayload['score_breakdown'],
        );
    }

    /**
     * @param array<string, mixed> $dnsPayload
     */
    private function normalized(array $dnsPayload): NormalizedScanResultDTO
    {
        return new NormalizedScanResultDTO(
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
    }
}
