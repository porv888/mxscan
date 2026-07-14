<?php

namespace App\Domain\EmailSecurity\Scoring;

use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DTO\ScoreResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;
use App\Services\ScoreBreakdownService;
use Illuminate\Support\Facades\Log;

/**
 * Phase 1 adapter — preserves ScannerService score as authoritative and validates breakdown alignment.
 */
final class LegacyDnsScoreCalculator implements ScoreCalculatorInterface
{
    public function __construct(
        private ScoreBreakdownService $scoreBreakdownService,
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
            return new ScoreResultDTO(total: null, breakdown: []);
        }

        $total = isset($dns['score']) ? (int) $dns['score'] : null;
        $breakdown = $dns['score_breakdown'] ?? $input->scoreBreakdown;

        if ($breakdown === [] && isset($dns['records']) && is_array($dns['records'])) {
            $breakdown = $this->scoreBreakdownService->buildFromDnsRecords($dns['records']);
        }

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
}
