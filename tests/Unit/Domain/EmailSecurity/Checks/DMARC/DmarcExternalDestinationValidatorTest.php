<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcExternalDestinationValidator;
use Tests\Support\EmailSecurity\FakeDmarcDnsResolver;
use Tests\TestCase;

class DmarcExternalDestinationValidatorTest extends TestCase
{
    public function test_external_destination_authorized(): void
    {
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord('example.test._report._dmarc.external.com', 'v=DMARC1');
        $validator = new DmarcExternalDestinationValidator($resolver);

        $result = $validator->validateAggregateDestinations(
            [[
                'normalized_destination' => 'reports@external.com',
                'destination_domain' => 'external.com',
            ]],
            'example.test',
            'example.test',
        );

        $this->assertSame('authorized', $result['destinations'][0]['authorization_status'] ?? null);
        $this->assertSame('example.test._report._dmarc.external.com', $result['destinations'][0]['authorization_lookup_name'] ?? null);
        $this->assertSame(0, $result['unauthorized_count']);
    }

    public function test_external_destination_unauthorized(): void
    {
        $resolver = new FakeDmarcDnsResolver();
        $resolver->setRecord('example.test._report._dmarc.external.com', null);
        $validator = new DmarcExternalDestinationValidator($resolver);

        $result = $validator->validateAggregateDestinations(
            [[
                'normalized_destination' => 'reports@external.com',
                'destination_domain' => 'external.com',
            ]],
            'example.test',
            'example.test',
        );

        $this->assertSame('unauthorized', $result['destinations'][0]['authorization_status'] ?? null);
        $this->assertSame(1, $result['unauthorized_count']);
    }

    public function test_internal_destination_skips_authorization_lookup(): void
    {
        $resolver = new FakeDmarcDnsResolver();
        $validator = new DmarcExternalDestinationValidator($resolver);

        $result = $validator->validateAggregateDestinations(
            [[
                'normalized_destination' => 'dmarc@example.test',
                'destination_domain' => 'example.test',
            ]],
            'example.test',
            'example.test',
        );

        $this->assertTrue($result['destinations'][0]['internal'] ?? false);
        $this->assertSame('not_required', $result['destinations'][0]['authorization_status'] ?? null);
    }
}
