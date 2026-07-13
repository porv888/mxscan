<?php

namespace Tests\Unit;

use App\Models\BlacklistResult;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\User;
use App\Services\BlacklistChecker;
use Illuminate\Support\Str;
use Tests\Concerns\UsesSqliteDmarcSchema;
use Tests\TestCase;

class BlacklistCheckerSummaryTest extends TestCase
{
    use UsesSqliteDmarcSchema;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSqliteDmarcSchema();
        $this->setUpSqliteMonitoringExtras();
    }

    protected function makeScan(): Scan
    {
        $user = User::factory()->create();
        $domain = Domain::create([
            'user_id' => $user->id,
            'domain' => 'bl-' . Str::random(8) . '.test',
            'dmarc_token' => Str::random(24),
        ]);

        return Scan::create([
            'id' => (string) Str::uuid(),
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'type' => 'blacklist',
            'status' => 'finished',
            'finished_at' => now(),
        ]);
    }

    public function test_zero_results_is_not_clean(): void
    {
        $scan = $this->makeScan();
        $summary = (new BlacklistChecker())->getScanSummary($scan);

        $this->assertSame(0, $summary['total_checks']);
        $this->assertSame(0, $summary['listed_count']);
        $this->assertFalse($summary['is_clean']);
    }

    public function test_checks_with_zero_listed_is_clean(): void
    {
        $scan = $this->makeScan();
        BlacklistResult::create([
            'scan_id' => $scan->id,
            'provider' => 'zen.spamhaus.org',
            'ip_address' => '1.2.3.4',
            'status' => 'ok',
        ]);
        BlacklistResult::create([
            'scan_id' => $scan->id,
            'provider' => 'bl.spamcop.net',
            'ip_address' => '1.2.3.4',
            'status' => 'ok',
        ]);

        $summary = (new BlacklistChecker())->getScanSummary($scan);

        $this->assertSame(2, $summary['total_checks']);
        $this->assertSame(0, $summary['listed_count']);
        $this->assertTrue($summary['is_clean']);
    }

    public function test_listed_results_are_not_clean(): void
    {
        $scan = $this->makeScan();
        BlacklistResult::create([
            'scan_id' => $scan->id,
            'provider' => 'zen.spamhaus.org',
            'ip_address' => '1.2.3.4',
            'status' => 'listed',
        ]);
        BlacklistResult::create([
            'scan_id' => $scan->id,
            'provider' => 'bl.spamcop.net',
            'ip_address' => '1.2.3.4',
            'status' => 'ok',
        ]);

        $summary = (new BlacklistChecker())->getScanSummary($scan);

        $this->assertSame(2, $summary['total_checks']);
        $this->assertSame(1, $summary['listed_count']);
        $this->assertFalse($summary['is_clean']);
    }
}
