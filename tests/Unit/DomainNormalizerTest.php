<?php

namespace Tests\Unit;

use App\Support\DomainNormalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DomainNormalizerTest extends TestCase
{
    #[DataProvider('validInputs')]
    public function test_normalizes_to_example_com(string $input): void
    {
        $this->assertSame('example.com', DomainNormalizer::normalize($input));
    }

    public static function validInputs(): array
    {
        return [
            ['example.com'],
            ['EXAMPLE.COM'],
            ['www.example.com'],
            ['https://example.com'],
            ['https://www.example.com/'],
            ['https://example.com/path'],
            ['example.com/path?x=1'],
            ['example.com#section'],
            ['  https://www.example.com/foo?bar=1#x  '],
        ];
    }

    public function test_preserves_non_www_subdomains(): void
    {
        $this->assertSame('mail.example.com', DomainNormalizer::normalize('https://mail.example.com/path'));
    }

    #[DataProvider('invalidInputs')]
    public function test_rejects_invalid_inputs(string $input): void
    {
        $this->assertNull(DomainNormalizer::normalize($input));
    }

    public static function invalidInputs(): array
    {
        return [
            [''],
            ['   '],
            ['not a domain'],
            ['http://'],
            ['192.168.1.1'],
            ['https://127.0.0.1/'],
            ['::1'],
            ['localhost'],
            ['example'],
        ];
    }
}
