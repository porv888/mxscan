<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiLogoRasterizer;
use Tests\Support\EmailSecurity\BimiTestFixtures;
use Tests\TestCase;

class BimiLogoRasterizerTest extends TestCase
{
    public function test_rasterize_returns_png_or_null_without_throwing(): void
    {
        $rasterizer = new BimiLogoRasterizer();
        $png = $rasterizer->rasterize(BimiTestFixtures::VALID_SVG);

        if (!extension_loaded('imagick') && !function_exists('imagecreatefromstring')) {
            $this->markTestSkipped('Neither Imagick nor GD SVG rendering is available.');
        }

        if ($png === null) {
            $this->markTestSkipped('SVG rasterization is unavailable in this environment.');
        }

        $this->assertStringStartsWith("\x89PNG\r\n\x1a\n", $png);
    }
}
