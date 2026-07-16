<?php

namespace Tests\Unit\Domain\EmailSecurity\Recommendations;

use App\Domain\EmailSecurity\Recommendations\RecommendationRanker;
use PHPUnit\Framework\TestCase;

class RecommendationRankerTest extends TestCase
{
    public function test_severity_always_precedes_remediation_sequence(): void
    {
        $ranked = (new RecommendationRanker())->sort([
            ['key' => 'mtasts', 'severity' => 'low'],
            ['key' => 'certificates', 'severity' => 'medium'],
            ['key' => 'dmarc_strengthen', 'severity' => 'low'],
            ['key' => 'spf_missing', 'severity' => 'high'],
        ]);

        $this->assertSame(
            ['spf_missing', 'certificates', 'mtasts', 'dmarc_strengthen'],
            array_column($ranked, 'key'),
        );
    }
}
