<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorNormalizer;
use Tests\TestCase;

class DkimSelectorNormalizerTest extends TestCase
{
    public function test_accepts_valid_selector(): void
    {
        $normalizer = new DkimSelectorNormalizer();
        $result = $normalizer->normalize('Google2024', 'example.com');

        $this->assertSame('google2024', $result['selector']);
        $this->assertSame('google2024._domainkey.example.com', $result['hostname']);
    }

    public function test_rejects_traversal_and_invalid_chars(): void
    {
        $normalizer = new DkimSelectorNormalizer();

        $this->assertNull($normalizer->normalize('../evil', 'example.com'));
        $this->assertNull($normalizer->normalize('bad selector', 'example.com'));
        $this->assertNull($normalizer->normalize('a._domainkey.b', 'example.com'));
    }
}
