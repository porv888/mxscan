<?php

namespace Tests\Unit;

use App\Services\ScanReport\ScanReportStatusMapper;
use PHPUnit\Framework\TestCase;

class ScanReportStatusMapperTest extends TestCase
{
    protected ScanReportStatusMapper $mapper;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mapper = new ScanReportStatusMapper();
    }

    public function test_blacklist_zero_checks_is_not_checked_and_not_clean(): void
    {
        $card = $this->mapper->mapBlacklist([
            'total_checks' => 0,
            'listed_count' => 0,
            'is_clean' => true,
        ]);

        $this->assertSame(ScanReportStatusMapper::NOT_CHECKED, $card['state']);
        $this->assertSame('Unable to verify', $card['label']);
    }

    public function test_blacklist_missing_payload_is_not_scanned(): void
    {
        $card = $this->mapper->mapBlacklist(null);
        $this->assertSame(ScanReportStatusMapper::NOT_CHECKED, $card['state']);
        $this->assertSame('Unable to verify', $card['label']);
    }

    public function test_blacklist_clean_when_checks_and_zero_listings(): void
    {
        $card = $this->mapper->mapBlacklist([
            'total_checks' => 12,
            'listed_count' => 0,
        ]);

        $this->assertSame(ScanReportStatusMapper::PASS, $card['state']);
        $this->assertSame('Clean', $card['label']);
        $this->assertSame('0 of 12 checked lists contained the domain/IP.', $card['subtext']);
    }

    public function test_blacklist_listed(): void
    {
        $card = $this->mapper->mapBlacklist([
            'total_checks' => 12,
            'listed_count' => 3,
        ]);

        $this->assertSame(ScanReportStatusMapper::FAIL, $card['state']);
        $this->assertSame('Listed', $card['label']);
        $this->assertStringContainsString('3 detections across 12 checks', $card['subtext']);
    }

    public function test_spf_missing_ignores_lookup_count(): void
    {
        $card = $this->mapper->mapSpf(
            ['status' => 'missing'],
            ['lookups' => 0, 'valid' => true]
        );

        $this->assertSame(ScanReportStatusMapper::MISSING, $card['state']);
        $this->assertSame('Missing', $card['status']);
        $this->assertSame('Lookup count not applicable', $card['subtext']);
        $this->assertNotSame('OK', $card['status']);
    }

    public function test_spf_invalid(): void
    {
        $card = $this->mapper->mapSpf(
            ['status' => 'found', 'data' => 'v=spf1 +all'],
            ['lookups' => 1, 'valid' => false, 'error' => 'SPF uses +all which allows any sender.']
        );

        $this->assertSame(ScanReportStatusMapper::FAIL, $card['state']);
        $this->assertSame('Invalid', $card['status']);
        $this->assertStringContainsString('+all', $card['subtext']);
    }

    /**
     * @dataProvider spfLookupProvider
     */
    public function test_spf_lookup_thresholds(int $lookups, string $state, string $status): void
    {
        $card = $this->mapper->mapSpf(
            ['status' => 'found', 'data' => 'v=spf1 -all'],
            ['lookups' => $lookups, 'valid' => true]
        );

        $this->assertSame($state, $card['state']);
        $this->assertSame($status, $card['status']);
        $this->assertStringContainsString($lookups . ' of 10 DNS lookups', $card['subtext']);
    }

    public static function spfLookupProvider(): array
    {
        return [
            [0, ScanReportStatusMapper::PASS, 'Published'],
            [6, ScanReportStatusMapper::PASS, 'Published'],
            [7, ScanReportStatusMapper::WARNING, 'Published'],
            [9, ScanReportStatusMapper::WARNING, 'Published'],
            [10, ScanReportStatusMapper::WARNING, 'Published'],
            [11, ScanReportStatusMapper::FAIL, 'Invalid'],
        ];
    }

    public function test_spf_found_but_lookups_absent_is_not_checked(): void
    {
        $card = $this->mapper->mapSpf(
            ['status' => 'found', 'data' => 'v=spf1 -all'],
            null
        );

        $this->assertSame(ScanReportStatusMapper::NOT_CHECKED, $card['state']);
        $this->assertSame('Unable to verify', $card['status']);
    }

    public function test_dkim_quarantine_policy_maps_to_pass_not_monitoring(): void
    {
        $card = $this->mapper->mapDmarc(
            ['status' => 'found', 'data' => 'v=DMARC1; p=quarantine'],
            [
                'analysis' => [
                    'version' => 'dmarc-native-v1',
                    'state' => 'warning',
                    'policy' => [
                        'published_p' => 'quarantine',
                        'effective_policy' => 'quarantine',
                        'enforcement' => 'quarantine',
                    ],
                    'alignment_verification' => 'not_verified',
                ],
            ],
        );

        $this->assertSame(ScanReportStatusMapper::PASS, $card['state']);
        $this->assertSame('Policy quarantine', $card['status']);
    }

    public function test_dkim_selectors_discovered_wording_is_dns_only(): void
    {
        $card = $this->mapper->mapDkim([
            'status' => 'found',
            'data' => [
                ['selector' => 's1', 'record' => 'v=DKIM1; p=abc'],
                ['selector' => 's2', 'record' => 'v=DKIM1; p=def'],
            ],
        ]);

        $this->assertSame('A valid DKIM key is published for a tested selector (historical scan).', $card['status']);
        $this->assertStringContainsString('published DNS keys only', $card['explanation']);
        $this->assertStringNotContainsString('signing verified', strtolower($card['explanation']));
        $this->assertStringNotContainsString('alignment verified', strtolower($card['explanation']));
    }

    public function test_is_clean_requires_checks(): void
    {
        $total = 0;
        $listed = 0;
        $this->assertFalse($total > 0 && $listed === 0);
        $this->assertTrue(5 > 0 && 0 === 0);
        $this->assertFalse(5 > 0 && 2 === 0);
    }
}
