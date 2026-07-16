<?php

namespace App\Domain\EmailSecurity\Recommendations;

final class RecommendationRanker
{
    /**
     * @param list<array<string, mixed>> $recommendations
     * @return list<array<string, mixed>>
     */
    public function sort(array $recommendations): array
    {
        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'optional' => 4];

        foreach ($recommendations as $index => &$recommendation) {
            $recommendation['_source_order'] = $index;
        }
        unset($recommendation);

        usort($recommendations, function (array $a, array $b) use ($severityOrder): int {
            $aSeverity = $severityOrder[$a['severity'] ?? 'medium'] ?? 2;
            $bSeverity = $severityOrder[$b['severity'] ?? 'medium'] ?? 2;

            // Severity is always the first ordering invariant.
            $severity = $aSeverity <=> $bSeverity;
            if ($severity !== 0) {
                return $severity;
            }

            $remediation = $this->remediationOrder($a) <=> $this->remediationOrder($b);
            if ($remediation !== 0) {
                return $remediation;
            }

            return ($a['_source_order'] ?? 0) <=> ($b['_source_order'] ?? 0);
        });

        foreach ($recommendations as &$recommendation) {
            unset($recommendation['_source_order']);
        }
        unset($recommendation);

        return array_values($recommendations);
    }

    private function remediationOrder(array $recommendation): int
    {
        $key = (string) ($recommendation['key'] ?? $recommendation['legacy_key'] ?? '');
        $semantic = (string) ($recommendation['semantic_key'] ?? '');

        return match (true) {
            str_starts_with($key, 'spf'), str_contains($semantic, 'spf') => 10,
            str_starts_with($key, 'dmarc_rua'), str_contains($semantic, 'dmarc_reporting') => 20,
            $key === 'mtasts', str_contains($semantic, 'mta_sts') => 30,
            in_array($key, ['tlsrpt', 'certificates'], true),
            str_contains($semantic, 'tls_rpt'),
            str_contains($semantic, 'certificate') => 40,
            $semantic === 'strengthen_dmarc_policy' => 90,
            ($recommendation['severity'] ?? '') === 'optional',
            str_contains($semantic, 'bimi') => 100,
            default => 50,
        };
    }
}
