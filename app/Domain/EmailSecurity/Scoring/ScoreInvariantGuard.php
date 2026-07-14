<?php

namespace App\Domain\EmailSecurity\Scoring;

use App\Services\ScoreBreakdownService;

final class ScoreInvariantGuard
{
    public function __construct(
        private ScoreBreakdownService $scoreBreakdownService,
    ) {
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     */
    public function assertConsistent(?int $total, array $breakdown): void
    {
        if ($total === null) {
            return;
        }

        $earned = $this->scoreBreakdownService->totalEarned($breakdown);
        if ($earned === $total) {
            return;
        }

        throw new ScoreInvariantViolationException(
            "Score invariant violated: declared total {$total} does not equal breakdown sum {$earned}."
        );
    }
}
