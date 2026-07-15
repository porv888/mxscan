<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use Tests\TestCase;

class DmarcParserTest extends TestCase
{
    public function test_parses_standard_tags(): void
    {
        $parsed = (new DmarcParser())->parse('v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com');

        $this->assertSame('DMARC1', $parsed->tags['v']['normalized'] ?? null);
        $this->assertSame('reject', $parsed->tags['p']['normalized'] ?? null);
        $this->assertSame('100', $parsed->tags['pct']['normalized'] ?? null);
    }

    public function test_version_tag_must_be_dmarc1_for_reconstruction(): void
    {
        $this->assertFalse(
            \App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor::isDmarcVersionToken('v=DMARC10')
        );
        $this->assertTrue(
            \App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor::isDmarcVersionToken('v=DMARC1')
        );
    }
}
