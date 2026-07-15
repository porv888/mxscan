<?php

namespace App\Domain\EmailSecurity\Scoring;

use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DTO\ScoreResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;
use App\Domain\EmailSecurity\Checks\Bimi\Scoring\BimiScoreRule;
use App\Domain\EmailSecurity\Checks\Certificates\Scoring\CertificateScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\DkimScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\DmarcScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\MxScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\MtaStsScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\TlsRptScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\SpfScoreRule;
use App\Services\ScoreBreakdownService;
use Illuminate\Support\Facades\Log;

/**
 * Phase 1 adapter — preserves ScannerService score as authoritative and validates breakdown alignment.
 */
final class LegacyDnsScoreCalculator implements ScoreCalculatorInterface
{
    public function __construct(
        private ScoreBreakdownService $scoreBreakdownService,
        private SpfScoreRule $spfScoreRule,
        private DmarcScoreRule $dmarcScoreRule,
        private DkimScoreRule $dkimScoreRule,
        private MtaStsScoreRule $mtaStsScoreRule,
        private TlsRptScoreRule $tlsRptScoreRule,
        private MxScoreRule $mxScoreRule,
        private CertificateScoreRule $certificateScoreRule,
        private BimiScoreRule $bimiScoreRule,
        private ScoreInvariantGuard $scoreInvariantGuard,
    ) {
    }

    public function calculate(ScoringInputDTO $input): ScoreResultDTO
    {
        $legacy = $input->normalized->legacyDnsMetadata;
        $dns = is_array($legacy['legacy_payload'] ?? null)
            ? $legacy['legacy_payload']
            : [
                'score' => $legacy['score'] ?? null,
                'records' => $legacy['records'] ?? [],
                'score_breakdown' => $legacy['score_breakdown'] ?? [],
            ];

        if ($legacy === [] && $dns === []) {
            if ($this->usesNativeScoring($input)) {
                return $this->scoreNativeOnly($input);
            }

            return new ScoreResultDTO(total: null, breakdown: []);
        }

        $breakdown = $dns['score_breakdown'] ?? $input->scoreBreakdown;

        if ($breakdown === [] && isset($dns['records']) && is_array($dns['records'])) {
            $breakdown = $this->scoreBreakdownService->buildFromDnsRecords($dns['records']);
        }

        if ($this->usesNativeScoring($input)) {
            return $this->scoreNativeWithBreakdown($input, $breakdown);
        }

        $total = isset($dns['score']) ? (int) $dns['score'] : null;

        if ($total !== null) {
            $earned = $this->scoreBreakdownService->totalEarned($breakdown);
            if ($earned !== $total) {
                Log::debug('Email security score breakdown mismatch', [
                    'scanner_total' => $total,
                    'breakdown_total' => $earned,
                ]);
            }
        }

        return new ScoreResultDTO(total: $total, breakdown: $breakdown);
    }

    private function usesNativeScoring(ScoringInputDTO $input): bool
    {
        return $this->usesNativeSpfScoring($input)
            || $input->nativeDmarcResult !== null
            || $input->nativeDkimResult !== null
            || $input->nativeMtaStsResult !== null
            || $input->nativeTlsRptResult !== null
            || $input->nativeMxResult !== null
            || $input->nativeCertificateResult !== null
            || $input->nativeBimiResult !== null;
    }

    private function usesNativeSpfScoring(ScoringInputDTO $input): bool
    {
        return config('email-security.spf_engine', 'legacy') === 'native'
            && $input->nativeSpfResult !== null;
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     */
    private function scoreNativeWithBreakdown(ScoringInputDTO $input, array $breakdown): ScoreResultDTO
    {
        $breakdown = $this->applyNativeComponents($input, $breakdown);
        $total = $this->scoreBreakdownService->totalEarned($breakdown);
        $this->scoreInvariantGuard->assertConsistent($total, $breakdown);

        return new ScoreResultDTO(total: $total, breakdown: $breakdown);
    }

    private function scoreNativeOnly(ScoringInputDTO $input): ScoreResultDTO
    {
        $breakdown = $this->applyNativeComponents($input, []);
        $total = $this->scoreBreakdownService->totalEarned($breakdown);
        $this->scoreInvariantGuard->assertConsistent($total, $breakdown);

        return new ScoreResultDTO(total: $total, breakdown: $breakdown);
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @return list<array<string, mixed>>
     */
    private function applyNativeComponents(ScoringInputDTO $input, array $breakdown): array
    {
        if ($this->usesNativeSpfScoring($input)) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->spfScoreRule->score($input->nativeSpfResult),
            );
        }

        if ($input->nativeDmarcResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->dmarcScoreRule->score($input->nativeDmarcResult),
            );
        }

        if ($input->nativeDkimResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->dkimScoreRule->score($input->nativeDkimResult),
            );
        }

        if ($input->nativeMtaStsResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->mtaStsScoreRule->score($input->nativeMtaStsResult),
            );
        }

        if ($input->nativeTlsRptResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->tlsRptScoreRule->score($input->nativeTlsRptResult),
            );
        }

        if ($input->nativeMxResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->mxScoreRule->score($input->nativeMxResult),
            );
        }

        if ($input->nativeCertificateResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->certificateScoreRule->score($input->nativeCertificateResult),
            );
        }

        if ($input->nativeBimiResult !== null) {
            $breakdown = $this->scoreBreakdownService->replaceComponent(
                $breakdown,
                $this->bimiScoreRule->score($input->nativeBimiResult),
            );
        }

        return $breakdown;
    }
}
