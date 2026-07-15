<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Inspection\DkimPublicKeyInspector;
use Tests\Support\EmailSecurity\FixtureLoader;
use Tests\TestCase;

class DkimPublicKeyInspectorTest extends TestCase
{
    public function test_valid_rsa_2048_key(): void
    {
        $record = FixtureLoader::TEST_RSA_2048_DKIM_RECORD;
        preg_match('/p=([^;]+)/', $record, $matches);
        $p = $matches[1] ?? '';

        $result = (new DkimPublicKeyInspector())->inspect('rsa', $p);

        $this->assertTrue($result['valid']);
        $this->assertSame('rsa', $result['type']);
        $this->assertGreaterThanOrEqual(2048, $result['bits']);
        $this->assertFalse($result['revoked']);
    }

    public function test_empty_public_key_is_revoked(): void
    {
        $result = (new DkimPublicKeyInspector())->inspect('rsa', '');

        $this->assertTrue($result['revoked']);
        $this->assertFalse($result['valid']);
        $this->assertSame('REVOKED_KEY', $result['error']);
    }

    public function test_invalid_base64_is_rejected(): void
    {
        $result = (new DkimPublicKeyInspector())->inspect('rsa', '!!!not-base64!!!');

        $this->assertFalse($result['valid']);
        $this->assertSame('INVALID_BASE64', $result['error']);
    }
}
