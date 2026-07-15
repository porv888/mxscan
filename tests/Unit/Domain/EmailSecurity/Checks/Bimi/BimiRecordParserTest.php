<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\BimiRecordParser;
use Tests\TestCase;

class BimiRecordParserTest extends TestCase
{
    private BimiRecordParser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = app(BimiRecordParser::class);
    }

    public function test_parses_valid_record(): void
    {
        $parsed = $this->parser->parse('v=BIMI1; l=https://example.test/logo.svg; a=; avp=brand;');
        $this->assertSame('BIMI1', $parsed->tag('v'));
        $this->assertSame('https://example.test/logo.svg', $parsed->tag('l'));
        $this->assertSame('brand', $parsed->avatarPreference);
    }

    public function test_detects_explicit_declination(): void
    {
        $parsed = $this->parser->parse('v=BIMI1; l=; a=;');
        $this->assertTrue($parsed->declined);
    }

    public function test_defaults_avp_to_brand(): void
    {
        $parsed = $this->parser->parse('v=BIMI1; l=https://example.test/logo.svg;');
        $this->assertSame('brand', $parsed->avatarPreference);
    }

    public function test_parses_avp_personal(): void
    {
        $parsed = $this->parser->parse('v=BIMI1; l=https://example.test/logo.svg; avp=personal;');
        $this->assertSame('personal', $parsed->avatarPreference);
    }
}
