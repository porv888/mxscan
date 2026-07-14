<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use Tests\TestCase;

class SpfLookupCounterTest extends TestCase
{
    public function test_allows_exactly_ten_lookups(): void
    {
        $counter = new SpfLookupCounter();

        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($counter->increment('include', "inc{$i}.test", 'TXT'));
        }

        $this->assertSame(10, $counter->count());
        $this->assertTrue($counter->atLimit());
        $this->assertFalse($counter->exceeded());
        $this->assertFalse($counter->attemptedOverLimit());
    }

    public function test_eleventh_lookup_attempt_is_over_limit(): void
    {
        $counter = new SpfLookupCounter();

        for ($i = 0; $i < 10; $i++) {
            $counter->increment('include', "inc{$i}.test", 'TXT');
        }

        $this->assertFalse($counter->increment('include', 'inc10.test', 'TXT'));
        $this->assertTrue($counter->attemptedOverLimit());
        $this->assertFalse($counter->exceeded());
    }
}
