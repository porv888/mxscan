<?php

namespace Tests\Unit;

use App\Services\Dmarc\DmarcDnsLookup;
use PHPUnit\Framework\TestCase;

class DmarcDnsLookupTest extends TestCase
{
    protected DmarcDnsLookup $lookup;

    protected function setUp(): void
    {
        parent::setUp();
        $this->lookup = new DmarcDnsLookup();
    }

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

        $reconstructed = $this->lookup->reconstructTxtFromRecord($record);

        $this->assertSame(
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
            $reconstructed
        );
    }

    public function test_multiple_unrelated_txt_records_plus_one_dmarc(): void
    {
        $rows = [
            [
                'host' => '_dmarc.example.com',
                'type' => 'TXT',
                'txt' => 'google-site-verification=abc123',
            ],
            [
                'host' => '_dmarc.example.com',
                'type' => 'TXT',
                'txt' => 'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
            ],
            [
                'host' => '_dmarc.example.com',
                'type' => 'TXT',
                'txt' => 'some-other-txt=value',
            ],
        ];

        $reconstructed = $this->lookup->reconstructAllTxt($rows);
        $selected = $this->lookup->selectDmarcRecord($reconstructed);

        $this->assertCount(3, $reconstructed);
        $this->assertSame(
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+718d719760053ef030649861@mxscan.me',
            $selected
        );
    }

    public function test_select_dmarc_is_case_insensitive_on_version_tag(): void
    {
        $selected = $this->lookup->selectDmarcRecord([
            'unrelated',
            'V=DMARC1; p=none; rua=mailto:dmarc+tok@mxscan.me',
        ]);

        $this->assertSame('V=DMARC1; p=none; rua=mailto:dmarc+tok@mxscan.me', $selected);
    }

    public function test_txt_array_chunks_are_joined(): void
    {
        $reconstructed = $this->lookup->reconstructTxtFromRecord([
            'txt' => ['v=DMARC1; p=none; ', 'rua=mailto:dmarc+tok@mxscan.me'],
        ]);

        $this->assertSame('v=DMARC1; p=none; rua=mailto:dmarc+tok@mxscan.me', $reconstructed);
    }
}
