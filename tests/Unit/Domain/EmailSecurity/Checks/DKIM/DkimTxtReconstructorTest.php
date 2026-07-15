<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimTxtReconstructor;
use Tests\TestCase;

class DkimTxtReconstructorTest extends TestCase
{
    public function test_reconstructs_chunked_txt_entries(): void
    {
        $value = DkimTxtReconstructor::fromDnsRow([
            'entries' => ['v=DKIM1; k=rsa; p=abc', 'def'],
        ]);

        $this->assertSame('v=DKIM1; k=rsa; p=abcdef', $value);
    }

    public function test_reconstructs_array_txt_field(): void
    {
        $value = DkimTxtReconstructor::fromDnsRow([
            'txt' => ['v=DKIM1', '; p=xyz'],
        ]);

        $this->assertSame('v=DKIM1; p=xyz', $value);
    }

    public function test_all_from_dns_rows_skips_empty_chunks(): void
    {
        $values = DkimTxtReconstructor::allFromDnsRows([
            ['txt' => 'v=DKIM1; p=one'],
            ['txt' => ''],
            ['entries' => ['v=DKIM1; p=two']],
        ]);

        $this->assertSame(['v=DKIM1; p=one', 'v=DKIM1; p=two'], $values);
    }

    public function test_looks_like_dkim_key(): void
    {
        $this->assertTrue(DkimTxtReconstructor::looksLikeDkimKey('v=DKIM1; k=rsa; p=abc'));
        $this->assertFalse(DkimTxtReconstructor::looksLikeDkimKey('v=spf1 -all'));
    }
}
