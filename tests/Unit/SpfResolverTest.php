<?php

namespace Tests\Unit;

use App\Services\Dns\DnsClient;
use App\Services\Spf\SpfResolver;
use Mockery;
use Tests\TestCase;

class SpfResolverTest extends TestCase
{
    private $mockDnsClient;
    private $spfResolver;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->mockDnsClient = Mockery::mock(DnsClient::class);
        $this->spfResolver = new SpfResolver($this->mockDnsClient);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_resolve_basic_ip4_record(): void
    {
        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn(['v=spf1 ip4:192.168.1.1 -all']);

        $result = $this->spfResolver->resolve('example.com');

        $this->assertEquals('v=spf1 ip4:192.168.1.1 -all', $result->currentRecord);
        $this->assertEquals(0, $result->lookupsUsed);
        $this->assertEquals('v=spf1 ip4:192.168.1.1 -all', $result->flattenedSpf);
        $this->assertEquals(['192.168.1.1'], $result->resolvedIps);
        $this->assertEmpty($result->warnings);
    }

    public function test_resolve_no_spf_record(): void
    {
        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn([]);

        $result = $this->spfResolver->resolve('example.com');

        $this->assertNull($result->currentRecord);
        $this->assertEquals(0, $result->lookupsUsed);
        $this->assertNull($result->flattenedSpf);
        $this->assertContains(SpfResolver::WARNING_NO_SPF, $result->warnings);
        $this->assertEmpty($result->resolvedIps);
    }

    public function test_resolve_include_mechanism(): void
    {
        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn(['v=spf1 include:_spf.google.com -all']);

        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('_spf.google.com')
            ->once()
            ->andReturn(['v=spf1 ip4:209.85.128.0/17 -all']);

        $result = $this->spfResolver->resolve('example.com');

        $this->assertEquals(1, $result->lookupsUsed);
        $this->assertContains('209.85.128.0/17', $result->resolvedIps);
    }

    public function test_resolve_lookup_limit_exceeded(): void
    {
        // Create SPF record with 11 includes to exceed limit
        $includes = [];
        for ($i = 1; $i <= 11; $i++) {
            $includes[] = "include:spf{$i}.example.com";
        }
        $spfRecord = 'v=spf1 ' . implode(' ', $includes) . ' -all';

        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn([$spfRecord]);

        // Mock responses for first 10 includes only
        for ($i = 1; $i <= 10; $i++) {
            $this->mockDnsClient->shouldReceive('getTxt')
                ->with("spf{$i}.example.com")
                ->once()
                ->andReturn(['v=spf1 ip4:192.168.1.' . $i . ' -all']);
        }

        $result = $this->spfResolver->resolve('example.com');

        $this->assertEquals(10, $result->lookupsUsed);
        $this->assertContains(SpfResolver::WARNING_LOOKUP_LIMIT, $result->warnings);
    }

    public function test_resolve_ptr_mechanism_warning(): void
    {
        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn(['v=spf1 ptr -all']);

        $result = $this->spfResolver->resolve('example.com');

        $this->assertContains(SpfResolver::WARNING_PTR_USED, $result->warnings);
        $this->assertEquals(1, $result->lookupsUsed);
    }

    public function test_resolve_plus_all_warning(): void
    {
        $this->mockDnsClient->shouldReceive('getTxt')
            ->with('example.com')
            ->once()
            ->andReturn(['v=spf1 ip4:192.168.1.1 +all']);

        $result = $this->spfResolver->resolve('example.com');

        $this->assertContains(SpfResolver::WARNING_PLUS_ALL, $result->warnings);
        $this->assertEquals('v=spf1 ip4:192.168.1.1 +all', $result->flattenedSpf);
    }

    public function test_parse_spf_record(): void
    {
        $parsed = $this->spfResolver->parse('v=spf1 ip4:192.168.1.1 include:_spf.google.com a mx -all');

        $this->assertArrayHasKey('mechanisms', $parsed);
        $this->assertArrayHasKey('modifiers', $parsed);
        $this->assertContains('ip4:192.168.1.1', $parsed['mechanisms']);
        $this->assertContains('include:_spf.google.com', $parsed['mechanisms']);
        $this->assertContains('a', $parsed['mechanisms']);
        $this->assertContains('mx', $parsed['mechanisms']);
        $this->assertContains('-all', $parsed['mechanisms']);
    }
}
