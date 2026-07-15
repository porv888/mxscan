<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;
use PHPUnit\Framework\TestCase;

class DmarcTxtReconstructorTest extends TestCase
{
    public function test_split_txt_chunks_reconstruct_into_same_record(): void
    {
        $record = [
            'host' => '_dmarc.example.com',
            'type' => 'TXT',
            'entries' => [
                'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,',
                'mailto:dmarc+718d719760053ef030649861@mxscan.me',
            ],
            'txt' => 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
        ];

        $reconstructed = DmarcTxtReconstructor::fromDnsRow($record);

        $this->assertSame(
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
            $reconstructed
        );
    }

    public function test_multiple_unrelated_txt_records_plus_one_dmarc(): void
    {
        $rows = [
            ['host' => '_dmarc.example.com', 'type' => 'TXT', 'txt' => 'google-site-verification=abc123'],
            ['host' => '_dmarc.example.com', 'type' => 'TXT', 'txt' => 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me'],
            ['host' => '_dmarc.example.com', 'type' => 'TXT', 'txt' => 'some-other-txt=value'],
        ];

        $reconstructed = DmarcTxtReconstructor::allFromDnsRows($rows);
        $selected = DmarcTxtReconstructor::selectDmarcRecords($reconstructed);

        $this->assertCount(3, $reconstructed);
        $this->assertSame([
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
        ], $selected);
    }

    public function test_rejects_dmarc10_version_token(): void
    {
        $this->assertFalse(DmarcTxtReconstructor::isDmarcVersionToken('v=DMARC10; p=none'));
        $this->assertTrue(DmarcTxtReconstructor::isDmarcVersionToken('V=DMARC1; p=none; rua=mailto:dmarc+tok@mxscan.me'));
    }
}
