<?php

namespace App\Domain\EmailSecurity\Recommendations;

use Illuminate\Support\Facades\Log;

final class RecommendationCollectionGuard
{
    /** @var array<string, int> */
    private const SEVERITY_RANK = [
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        'optional' => 4,
    ];

    /**
     * @param list<array<string, mixed>> $items
     * @return list<array<string, mixed>>
     */
    public function deduplicate(array $items): array
    {
        /** @var array<string, array<string, mixed>> $winners */
        $winners = [];

        foreach ($items as $item) {
            $semanticKey = $this->semanticKey($item);
            if ($semanticKey === null) {
                continue;
            }

            if (!isset($winners[$semanticKey])) {
                $winners[$semanticKey] = $item;

                continue;
            }

            $existing = $winners[$semanticKey];
            if ($this->shouldReplace($existing, $item)) {
                $this->logDuplicate($semanticKey, $existing, $item);
                $winners[$semanticKey] = $item;
            } else {
                $this->logDuplicate($semanticKey, $item, $existing);
            }
        }

        $deduped = array_values($winners);
        usort($deduped, fn (array $a, array $b) => ($a['priority'] ?? 99) <=> ($b['priority'] ?? 99));

        return $deduped;
    }

    /**
     * @param array<string, mixed> $item
     */
    private function semanticKey(array $item): ?string
    {
        $key = $item['semantic_key'] ?? $item['key'] ?? null;

        return is_string($key) && $key !== '' ? $key : null;
    }

    /**
     * @param array<string, mixed> $incumbent
     * @param array<string, mixed> $challenger
     */
    private function shouldReplace(array $incumbent, array $challenger): bool
    {
        $incumbentSeverity = self::SEVERITY_RANK[strtolower((string) ($incumbent['severity'] ?? 'medium'))] ?? 99;
        $challengerSeverity = self::SEVERITY_RANK[strtolower((string) ($challenger['severity'] ?? 'medium'))] ?? 99;

        if ($challengerSeverity !== $incumbentSeverity) {
            return $challengerSeverity < $incumbentSeverity;
        }

        $incumbentPriority = (int) ($incumbent['priority'] ?? 99);
        $challengerPriority = (int) ($challenger['priority'] ?? 99);

        if ($challengerPriority !== $incumbentPriority) {
            return $challengerPriority < $incumbentPriority;
        }

        return strcmp((string) ($challenger['title'] ?? ''), (string) ($incumbent['title'] ?? '')) < 0;
    }

    /**
     * @param array<string, mixed> $rejected
     * @param array<string, mixed> $kept
     */
    private function logDuplicate(string $semanticKey, array $rejected, array $kept): void
    {
        if (!app()->environment(['local', 'testing'])) {
            return;
        }

        Log::debug('Duplicate recommendation semantic key suppressed', [
            'semantic_key' => $semanticKey,
            'rejected_source_rule' => $rejected['source_rule'] ?? $rejected['semantic_key'] ?? $rejected['key'] ?? null,
            'kept_source_rule' => $kept['source_rule'] ?? $kept['semantic_key'] ?? $kept['key'] ?? null,
        ]);
    }
}
