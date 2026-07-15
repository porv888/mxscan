<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\BimiProtocolStatus;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiPublicPrivacyFilter;
use Tests\TestCase;

class BimiPublicPrivacyFilterTest extends TestCase
{
    public function test_filter_strips_sensitive_fields(): void
    {
        $filter = new BimiPublicPrivacyFilter();
        $summary = $filter->filter([
            'summary' => 'BIMI record found.',
            'protocol_status' => BimiProtocolStatus::VALID,
            'readiness_status' => 'partially_ready',
            'record_hostname' => 'default._bimi.example.test',
            'selector' => ['record_hostname' => 'default._bimi.example.test'],
            'record' => [
                'tags' => [
                    'l' => ['raw' => 'https://example.test/logo.svg'],
                    'a' => ['raw' => 'https://example.test/vmc.pem'],
                ],
            ],
            'indicator' => [
                'status' => 'valid',
                'sha256' => str_repeat('a', 64),
                'fetch' => ['source_uri' => 'https://example.test/logo.svg', 'resolved_ips' => ['1.2.3.4']],
            ],
            'authority_evidence' => [
                'status' => 'valid',
                'type' => 'vmc',
                'fingerprint_sha256' => str_repeat('b', 64),
            ],
            'dmarc_eligibility' => ['core_eligible' => true],
        ]);

        $this->assertIsArray($summary);
        $this->assertSame('valid', $summary['logo_validation_status']);
        $this->assertTrue($summary['dmarc_core_eligible']);
        $this->assertArrayNotHasKey('sha256', $summary);
        $this->assertArrayNotHasKey('fetch', $summary);
        $encoded = json_encode($summary);
        $this->assertStringNotContainsString('logo.svg', $encoded);
        $this->assertStringNotContainsString('vmc.pem', $encoded);
    }

    public function test_legacy_dns_record_maps_to_privacy_summary(): void
    {
        $filter = new BimiPublicPrivacyFilter();
        $summary = $filter->filterFromResult(null, [
            'status' => 'found',
            'data' => [
                'raw_record' => 'v=BIMI1; l=https://legacy.test/logo.svg;',
                'logo_valid' => true,
                'logo_url' => 'https://legacy.test/logo.svg',
            ],
        ]);

        $this->assertIsArray($summary);
        $this->assertSame('valid', $summary['logo_validation_status']);
        $this->assertStringNotContainsString('legacy.test', json_encode($summary));
    }

    public function test_missing_record_returns_absent_logo_status(): void
    {
        $filter = new BimiPublicPrivacyFilter();
        $summary = $filter->filterFromResult(null, ['status' => 'missing']);

        $this->assertSame('absent', $summary['logo_validation_status']);
        $this->assertSame(BimiProtocolStatus::NONE, $summary['protocol_status']);
    }
}
