<?php

namespace App\Services;

use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

class ScoreBreakdownService
{
    /**
     * @return list<array{key: string, label: string, earned: int, possible: int, status: string, hint: ?string}>
     */
    public function buildFromDnsRecords(array $records): array
    {
        $items = [];

        $items[] = $this->scoreSpf($records['SPF'] ?? null);

        if (isset($records['BIMI'])) {
            $items[] = $this->scoreBimi($records['BIMI']);
        }

        return $items;
    }

    /**
     * @return list<array{key: string, label: string, earned: int, possible: int, status: string, hint: ?string}>
     */
    public function deductions(array $breakdown): array
    {
        return array_values(array_filter(
            $breakdown,
            fn (array $row) => ($row['possible'] ?? 0) > 0 && $row['earned'] < $row['possible']
        ));
    }

    public function totalEarned(array $breakdown): int
    {
        return min(
            (int) config('dns-scoring.cap', 100),
            array_sum(array_column($breakdown, 'earned'))
        );
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @return list<array<string, mixed>>
     */
    public function replaceComponent(array $breakdown, ScoreComponentDTO $component): array
    {
        $row = $component->toBreakdownRow();
        $replaced = false;

        foreach ($breakdown as $index => $existing) {
            if (($existing['key'] ?? '') === $component->key) {
                $breakdown[$index] = $row;
                $replaced = true;
                break;
            }
        }

        if (!$replaced) {
            $breakdown[] = $row;
        }

        return $breakdown;
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @return ?array<string, mixed>
     */
    public function findRow(array $breakdown, string $key): ?array
    {
        foreach ($breakdown as $row) {
            if (($row['key'] ?? '') === $key) {
                return $row;
            }
        }

        return null;
    }

    private function scoreSpf(?array $data): array
    {
        $base = (int) config('dns-scoring.spf.base', 20);
        $possible = $base;
        $found = ($data['status'] ?? '') === 'found';
        $earned = $found ? $base : 0;
        $hint = $found ? null : 'Publish an SPF TXT record to prevent spoofing.';

        return [
            'key' => 'spf',
            'label' => config('dns-scoring.spf.label', 'SPF Record'),
            'earned' => $earned,
            'possible' => $possible,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $hint,
        ];
    }

    private function scoreBimi(?array $data): array
    {
        // BIMI is optional and never contributes to or deducts from the score.
        $status = $data['status'] ?? 'missing';

        return [
            'key' => 'bimi',
            'label' => config('dns-scoring.bimi.label', 'BIMI'),
            'earned' => 0,
            'possible' => 0,
            'status' => $status,
            'hint' => 'Optional branding feature — does not affect Email Security Score.',
        ];
    }
}
