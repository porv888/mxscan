<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\DkimSignatureSelectorExtractor;
use Tests\TestCase;

class DkimSignatureSelectorExtractorTest extends TestCase
{
    public function test_extracts_selector_from_signature(): void
    {
        $extractor = new DkimSignatureSelectorExtractor();
        $header = 'v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed;';

        $this->assertSame('selector1', $extractor->extract($header));
    }
}
