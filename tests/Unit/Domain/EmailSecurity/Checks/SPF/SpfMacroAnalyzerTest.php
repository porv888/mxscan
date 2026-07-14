<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\SPF;

use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAnalyzer;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use Tests\TestCase;

class SpfMacroAnalyzerTest extends TestCase
{
    public function test_supported_d_macro_is_allowed(): void
    {
        $terms = (new SpfParser())->parse('v=spf1 include:%{d} -all', 'example.test');
        $assessment = (new SpfMacroAnalyzer())->assess($terms);

        $this->assertFalse($assessment->hasUnsupportedMacro);
    }

    public function test_unsupported_i_macro_is_detected(): void
    {
        $terms = (new SpfParser())->parse('v=spf1 include:%{i} -all', 'example.test');
        $assessment = (new SpfMacroAnalyzer())->assess($terms);

        $this->assertTrue($assessment->hasUnsupportedMacro);
        $this->assertContains('%{i}', $assessment->unsupportedTokens);
    }
}
