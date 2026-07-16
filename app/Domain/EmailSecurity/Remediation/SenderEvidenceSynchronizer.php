<?php

namespace App\Domain\EmailSecurity\Remediation;

use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Models\Domain;
use App\Models\DomainSender;

final class SenderEvidenceSynchronizer
{
    /**
     * Persist sender evidence from a completed scan without confirming it.
     *
     * @param array<string, mixed> $resultData
     */
    public function sync(Domain $domain, array $resultData): void
    {
        $seen = [];
        $mxAnalysis = MxAnalysisReader::analysis(
            is_array($resultData['mx'] ?? null) ? $resultData['mx'] : null
        );

        foreach ($mxAnalysis['targets'] ?? [] as $target) {
            if (!is_array($target)) {
                continue;
            }

            foreach (['a_addresses' => 'ip4', 'aaaa_addresses' => 'ip6'] as $key => $mechanism) {
                foreach ($target[$key] ?? [] as $address) {
                    $value = is_array($address) ? ($address['address'] ?? null) : $address;
                    if (!is_string($value) || $value === '') {
                        continue;
                    }

                    $seen[] = $this->upsertDetected(
                        $domain,
                        'own_server',
                        null,
                        $mechanism,
                        $value,
                    );
                }
            }
        }

        foreach ($this->detectedProviders($domain, $resultData) as $providerKey) {
            $provider = config("remediation.senders.{$providerKey}");
            if (!is_array($provider) || empty($provider['include'])) {
                continue;
            }

            $seen[] = $this->upsertDetected(
                $domain,
                'provider',
                $providerKey,
                'include',
                (string) $provider['include'],
            );
        }

        $domain->senders()
            ->where('source', DomainSender::SOURCE_DETECTED)
            ->when($seen !== [], fn ($query) => $query->whereNotIn('fingerprint', $seen))
            ->update(['is_active' => false]);
    }

    private function upsertDetected(
        Domain $domain,
        string $senderType,
        ?string $provider,
        string $mechanism,
        string $value,
    ): string {
        $fingerprint = DomainSender::fingerprint($senderType, $provider, $mechanism, $value);
        $sender = $domain->senders()->firstOrNew(['fingerprint' => $fingerprint]);

        $sender->fill([
            'sender_type' => $senderType,
            'provider' => $provider,
            'mechanism' => $mechanism,
            'value' => $value,
            'source' => DomainSender::SOURCE_DETECTED,
            'confidence' => $sender->exists
                ? $sender->confidence
                : DomainSender::CONFIDENCE_LIKELY,
            'confirmation_status' => $sender->exists
                ? $sender->confirmation_status
                : DomainSender::STATUS_PENDING,
            'last_seen_at' => now(),
            'is_active' => true,
        ]);
        $sender->save();

        return $fingerprint;
    }

    /**
     * @param array<string, mixed> $resultData
     * @return list<string>
     */
    private function detectedProviders(Domain $domain, array $resultData): array
    {
        $detected = [];
        $guess = strtolower((string) $domain->provider_guess);

        foreach (array_keys(config('remediation.senders', [])) as $key) {
            if ($guess !== '' && str_contains($guess, (string) $key)) {
                $detected[] = (string) $key;
            }
        }

        $analysis = DkimAnalysisReader::analysis(
            is_array($resultData['dkim'] ?? null) ? $resultData['dkim'] : null
        );
        $selectors = collect($analysis['selectors'] ?? [])
            ->filter(fn ($row) => is_array($row) && ($row['record_status'] ?? '') === 'valid')
            ->pluck('selector')
            ->filter()
            ->map(fn ($selector) => strtolower((string) $selector))
            ->all();

        foreach (config('remediation.senders', []) as $key => $provider) {
            if (array_intersect($selectors, $provider['dkim_selectors'] ?? []) !== []) {
                $detected[] = (string) $key;
            }
        }

        return array_values(array_unique($detected));
    }
}
