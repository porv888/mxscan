<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcDiscoveryResult;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\Checks\DMARC\Validation\DmarcValidator;
use Tests\TestCase;

class DmarcValidatorTest extends TestCase
{
    private DmarcValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new DmarcValidator(new DmarcParser());
    }

    public function test_missing_record_is_invalid(): void
    {
        $discovery = $this->discovery('example.test');
        $result = $this->validator->validate($discovery, null);

        $this->assertFalse($result->valid);
        $this->assertSame('DMARC_MISSING', $result->errors[0]['code'] ?? null);
    }

    public function test_multiple_records_is_invalid(): void
    {
        $discovery = new DmarcDiscoveryResult(
            queriedDomain: 'example.test',
            recordDomain: 'example.test',
            hostname: '_dmarc.example.test',
            source: 'dns_query',
            record: 'v=DMARC1; p=none',
            multipleRecords: true,
        );
        $result = $this->validator->validate($discovery, 'v=DMARC1; p=none');

        $this->assertFalse($result->valid);
        $this->assertSame('MULTIPLE_DMARC_RECORDS', $result->errors[0]['code'] ?? null);
    }

    public function test_invalid_policy_is_invalid(): void
    {
        $discovery = $this->discovery('example.test');
        $result = $this->validator->validate($discovery, 'v=DMARC1; p=invalid; rua=mailto:a@b.com');

        $this->assertFalse($result->valid);
        $this->assertSame('INVALID_POLICY', $result->errors[0]['code'] ?? null);
    }

    public function test_valid_record_passes(): void
    {
        $discovery = $this->discovery('example.test');
        $result = $this->validator->validate($discovery, 'v=DMARC1; p=quarantine; rua=mailto:a@b.com');

        $this->assertTrue($result->valid);
        $this->assertSame([], $result->errors);
    }

    private function discovery(string $domain): DmarcDiscoveryResult
    {
        return new DmarcDiscoveryResult(
            queriedDomain: $domain,
            recordDomain: $domain,
            hostname: '_dmarc.' . $domain,
            source: 'dns_query',
        );
    }
}
