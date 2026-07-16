<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantGuard;
use App\Domain\EmailSecurity\Recommendations\RecommendationRanker;
use App\Models\Domain;
use App\Models\Scan;

final class ScanPersister implements ScanPersisterInterface
{
    public function __construct(
        private ScoreInvariantGuard $scoreInvariantGuard,
        private RecommendationRanker $recommendationRanker,
    ) {
    }

    public function saveFinished(
        Scan $scan,
        Domain $domain,
        ScanExecutionResultDTO $execution,
        ScanOptionsDTO $options,
        array $factsJson,
    ): void {
        $breakdown = $execution->resultJson['dns']['score_breakdown'] ?? [];
        if ($execution->score !== null && $breakdown !== []) {
            $this->scoreInvariantGuard->assertConsistent($execution->score, $breakdown);
        }

        $scan->update([
            'status' => 'finished',
            'progress_pct' => 100,
            'type' => $execution->scanType,
            'score' => $execution->score,
            'facts_json' => $factsJson,
            'result_json' => $execution->resultJson,
            'recommendations_json' => $this->recommendationRanker->sort($execution->recommendations),
            'finished_at' => now(),
            'duration_ms' => $execution->durationMs,
        ]);
    }

    public function markFailed(Scan $scan, int $durationMs, ?string $userError = null): void
    {
        $payload = [];
        if ($userError !== null) {
            $payload['result_json'] = array_merge(
                is_array($scan->result_json) ? $scan->result_json : [],
                ['user_error' => $userError]
            );
        }

        $scan->update(array_merge([
            'status' => 'failed',
            'finished_at' => now(),
            'duration_ms' => $durationMs,
        ], $payload));
    }

    public function updateProgress(Scan $scan, int $progressPct): void
    {
        $scan->update(['progress_pct' => $progressPct]);
    }
}
