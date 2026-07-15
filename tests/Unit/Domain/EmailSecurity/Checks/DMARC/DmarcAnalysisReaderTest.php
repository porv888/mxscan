<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\TestCase;

class DmarcAnalysisReaderTest extends TestCase
{
    public function test_reads_native_analysis_from_dmarc_section(): void
    {
        $analysis = DmarcFixtureBuilder::nativeAnalysis(['effective_policy' => 'reject']);
        $analysis['policy']['effective_policy'] = 'reject';
        $dmarc = ['analysis' => $analysis];

        $this->assertSame('dmarc-native-v1', DmarcAnalysisReader::analysis($dmarc)['version'] ?? null);
        $this->assertSame('reject', DmarcAnalysisReader::effectivePolicy($dmarc));
        $this->assertSame('valid', DmarcAnalysisReader::protocolStatus($dmarc));
    }

    public function test_legacy_shim_from_dns_record(): void
    {
        $shim = DmarcAnalysisReader::fromLegacyDnsRecord(
            ['status' => 'found', 'data' => 'v=DMARC1; p=reject; rua=mailto:a@b.com'],
            null,
        );

        $this->assertSame('legacy-shim-v0', $shim['version']);
        $this->assertSame('reject', $shim['policy']['effective_policy'] ?? null);
        $this->assertTrue($shim['aggregate_reporting']['configured'] ?? false);
        $this->assertNotEmpty($shim['aggregate_reporting']['destinations'] ?? []);
    }

    public function test_missing_record_shim(): void
    {
        $shim = DmarcAnalysisReader::fromLegacyDnsRecord(null, null);

        $this->assertSame('none', $shim['protocol_status']);
        $this->assertSame('missing', $shim['state']);
    }
}
