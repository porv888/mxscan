<?php

namespace App\Domain\EmailSecurity\Remediation;

final readonly class SpfRemediationResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<string> $mechanisms
     */
    public function __construct(
        public string $state,
        public ?string $record,
        public string $policy,
        public int $score,
        public int $lookupCount,
        public array $errors,
        public array $warnings,
        public array $mechanisms,
        public bool $allSendersResolved,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'record' => $this->record,
            'type' => 'TXT',
            'host' => '@',
            'ttl' => 'Auto',
            'policy' => $this->policy,
            'score' => $this->score,
            'score_label' => $this->record === null ? 'Up to +20 points' : "+{$this->score} points",
            'lookup_count' => $this->lookupCount,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'mechanisms' => $this->mechanisms,
            'all_senders_resolved' => $this->allSendersResolved,
            'ready' => $this->state === 'Ready to publish',
        ];
    }
}
