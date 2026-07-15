<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use Illuminate\Support\Facades\Storage;
use Tests\Support\EmailSecurity\BimiTestFixtures;
use Tests\TestCase;

class BimiIndicatorPreviewStoreTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
    }

    public function test_store_and_retrieve_round_trip(): void
    {
        $store = new BimiIndicatorPreviewStore();
        $sha256 = BimiTestFixtures::validSvgSha256();

        $this->assertTrue($store->store('scan-1', $sha256, BimiTestFixtures::VALID_SVG));
        $this->assertSame(BimiTestFixtures::VALID_SVG, $store->retrieve('scan-1', $sha256));
        $this->assertTrue($store->exists('scan-1', $sha256));
    }

    public function test_null_scan_id_is_no_op(): void
    {
        $store = new BimiIndicatorPreviewStore();

        $this->assertFalse($store->store(null, BimiTestFixtures::validSvgSha256(), BimiTestFixtures::VALID_SVG));
    }

    public function test_hash_mismatch_returns_null(): void
    {
        $store = new BimiIndicatorPreviewStore();
        $sha256 = BimiTestFixtures::validSvgSha256();
        $store->store('scan-2', $sha256, BimiTestFixtures::VALID_SVG);

        $this->assertNull($store->retrieve('scan-2', str_repeat('a', 64)));
        $this->assertFalse($store->exists('scan-2', str_repeat('a', 64)));
    }

    public function test_oversize_svg_is_rejected(): void
    {
        config(['bimi.svg_max_bytes' => 10]);
        $store = new BimiIndicatorPreviewStore();

        $this->assertFalse($store->store('scan-3', BimiTestFixtures::validSvgSha256(), BimiTestFixtures::VALID_SVG));
    }
}
