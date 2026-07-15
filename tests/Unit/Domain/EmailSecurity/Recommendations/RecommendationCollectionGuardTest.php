<?php

namespace Tests\Unit\Domain\EmailSecurity\Recommendations;

use App\Domain\EmailSecurity\Recommendations\RecommendationCollectionGuard;
use Tests\TestCase;

class RecommendationCollectionGuardTest extends TestCase
{
    public function test_deduplicates_by_semantic_key_and_keeps_higher_severity(): void
    {
        $items = [
            [
                'semantic_key' => 'duplicate_key',
                'key' => 'legacy_a',
                'source_rule' => 'rule_low',
                'priority' => 5,
                'severity' => 'medium',
                'title' => 'Medium',
            ],
            [
                'semantic_key' => 'duplicate_key',
                'key' => 'legacy_b',
                'source_rule' => 'rule_high',
                'priority' => 4,
                'severity' => 'high',
                'title' => 'High',
            ],
        ];

        $deduped = (new RecommendationCollectionGuard())->deduplicate($items);

        $this->assertCount(1, $deduped);
        $this->assertSame('duplicate_key', $deduped[0]['semantic_key']);
        $this->assertSame('high', $deduped[0]['severity']);
        $this->assertSame('rule_high', $deduped[0]['source_rule']);
    }

    public function test_preserves_deterministic_priority_ordering(): void
    {
        $items = [
            ['semantic_key' => 'b', 'key' => 'b', 'priority' => 5, 'severity' => 'low', 'title' => 'B'],
            ['semantic_key' => 'a', 'key' => 'a', 'priority' => 3, 'severity' => 'high', 'title' => 'A'],
        ];

        $deduped = (new RecommendationCollectionGuard())->deduplicate($items);

        $this->assertSame(['a', 'b'], array_column($deduped, 'semantic_key'));
    }
}
