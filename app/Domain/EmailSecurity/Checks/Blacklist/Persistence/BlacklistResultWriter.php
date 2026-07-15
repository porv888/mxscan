<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Persistence;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistNativeResult;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistProviderRegistry;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistQueryOutcome;
use App\Models\BlacklistResult;

final class BlacklistResultWriter
{
    public function __construct(
        private BlacklistProviderRegistry $registry,
    ) {
    }

    public function write(string $scanId, BlacklistNativeResult $native): void
    {
        BlacklistResult::query()->where('scan_id', $scanId)->delete();

        foreach ($native->checks as $check) {
            $outcome = (string) ($check['outcome'] ?? '');
            if (!BlacklistQueryOutcome::isUsable($outcome)) {
                continue;
            }

            $provider = $this->registry->get((string) ($check['provider_key'] ?? ''));
            $status = BlacklistQueryOutcome::isListed($outcome) ? 'listed' : 'ok';

            BlacklistResult::create([
                'scan_id' => $scanId,
                'provider' => $provider?->name ?? (string) ($check['provider_name'] ?? 'Unknown'),
                'ip_address' => (string) ($check['target'] ?? ''),
                'status' => $status,
                'message' => $check['message'] ?? null,
                'removal_url' => $provider?->delistUrl,
            ]);
        }
    }
}
