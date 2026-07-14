<?php

namespace App\Domain\EmailSecurity\Scoring;

use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DTO\ScoreResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;
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
            if ($this->usesNativeSpfScoring($input)) {
                return $this->scoreNativeSpfOnly($input);
            }

            return new ScoreResultDTO(total: null, breakdown: []);
        }

        $breakdown = $dns['score_breakdown'] ?? $input->scoreBreakdown;

        if ($breakdown === [] && isset($dns['records']) && is_array($dns['records'])) {
            $breakdown = $this->scoreBreakdownService->buildFromDnsRecords($dns['records']);
        }

        if ($this->usesNativeSpfScoring($input)) {
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
        $component = $this->spfScoreRule->score($input->nativeSpfResult);
        $breakdown = $this->scoreBreakdownService->replaceComponent($breakdown, $component);
        $total = $this->scoreBreakdownService->totalEarned($breakdown);
        $this->scoreInvariantGuard->assertConsistent($total, $breakdown);

        return new ScoreResultDTO(total: $total, breakdown: $breakdown);
    }

    private function scoreNativeSpfOnly(ScoringInputDTO $input): ScoreResultDTO
    {
        $component = $this->spfScoreRule->score($input->nativeSpfResult);
        $breakdown = [$component->toBreakdownRow()];
        $total = $this->scoreBreakdownService->totalEarned($breakdown);
        $this->scoreInvariantGuard->assertConsistent($total, $breakdown);

        return new ScoreResultDTO(total: $total, breakdown: $breakdown);
    }
}
