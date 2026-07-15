<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Parsing\DkimRecordParser;
use Tests\TestCase;

class DkimRecordParserTest extends TestCase
{
    public function test_parses_known_tags(): void
    {
        $parsed = (new DkimRecordParser())->parse('v=DKIM1; k=rsa; p=abc; t=s; h=sha256');

        $this->assertSame('DKIM1', $parsed->tags['v'] ?? null);
        $this->assertSame('rsa', $parsed->tags['k'] ?? null);
        $this->assertSame('abc', $parsed->tags['p'] ?? null);
        $this->assertSame('s', $parsed->tags['t'] ?? null);
        $this->assertSame('sha256', $parsed->tags['h'] ?? null);
    }

    public function test_records_duplicate_tags(): void
    {
        $parsed = (new DkimRecordParser())->parse('v=DKIM1; p=one; p=two');

        $this->assertSame(['p' => ['two']], $parsed->duplicateTags);
    }

    public function test_flags_unknown_tags(): void
    {
        $parsed = (new DkimRecordParser())->parse('v=DKIM1; p=abc; x-custom=1');

        $this->assertContains('x-custom', $parsed->unknownTags);
    }
}
