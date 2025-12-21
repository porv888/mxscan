<?php

namespace Tests\Unit;

use App\Support\DomainAlign;
use PHPUnit\Framework\TestCase;

class DomainAlignTest extends TestCase
{
    /**
     * Test strict alignment mode
     */
    public function test_strict_alignment_requires_exact_match(): void
    {
        // Exact match should pass
        $this->assertTrue(DomainAlign::aligned('example.com', 'example.com', 's'));
        
        // Subdomain should fail in strict mode
        $this->assertFalse(DomainAlign::aligned('mail.example.com', 'example.com', 's'));
        $this->assertFalse(DomainAlign::aligned('example.com', 'mail.example.com', 's'));
        
        // Different domains should fail
        $this->assertFalse(DomainAlign::aligned('example.com', 'other.com', 's'));
    }

    /**
     * Test relaxed alignment mode
     */
    public function test_relaxed_alignment_allows_subdomains(): void
    {
        // Exact match should pass
        $this->assertTrue(DomainAlign::aligned('example.com', 'example.com', 'r'));
        
        // Subdomain should pass in relaxed mode
        $this->assertTrue(DomainAlign::aligned('mail.example.com', 'example.com', 'r'));
        $this->assertTrue(DomainAlign::aligned('example.com', 'mail.example.com', 'r'));
        
        // Multi-level subdomain should pass
        $this->assertTrue(DomainAlign::aligned('smtp.mail.example.com', 'example.com', 'r'));
        
        // Different organizational domains should fail
        $this->assertFalse(DomainAlign::aligned('example.com', 'other.com', 'r'));
        $this->assertFalse(DomainAlign::aligned('mail.example.com', 'other.com', 'r'));
    }

    /**
     * Test default mode is relaxed
     */
    public function test_default_mode_is_relaxed(): void
    {
        $this->assertTrue(DomainAlign::aligned('mail.example.com', 'example.com'));
    }

    /**
     * Test case insensitivity
     */
    public function test_alignment_is_case_insensitive(): void
    {
        $this->assertTrue(DomainAlign::aligned('Example.COM', 'example.com', 's'));
        $this->assertTrue(DomainAlign::aligned('MAIL.Example.COM', 'example.com', 'r'));
    }

    /**
     * Test empty domains
     */
    public function test_empty_domains_return_false(): void
    {
        $this->assertFalse(DomainAlign::aligned('', 'example.com'));
        $this->assertFalse(DomainAlign::aligned('example.com', ''));
        $this->assertFalse(DomainAlign::aligned('', ''));
    }

    /**
     * Test email domain extraction
     */
    public function test_extract_domain_from_email(): void
    {
        // Simple email
        $this->assertEquals('example.com', DomainAlign::extractDomain('user@example.com'));
        
        // Email with angle brackets
        $this->assertEquals('example.com', DomainAlign::extractDomain('"John Doe" <user@example.com>'));
        
        // Email with name
        $this->assertEquals('example.com', DomainAlign::extractDomain('John Doe <user@example.com>'));
        
        // Invalid email
        $this->assertNull(DomainAlign::extractDomain('not-an-email'));
        $this->assertNull(DomainAlign::extractDomain(''));
    }

    /**
     * Test organizational domain extraction
     */
    public function test_organizational_domain_extraction(): void
    {
        // Two-part domain
        $this->assertTrue(DomainAlign::aligned('mail.example.com', 'www.example.com', 'r'));
        
        // Three-part domain
        $this->assertTrue(DomainAlign::aligned('a.b.example.com', 'c.d.example.com', 'r'));
    }
}
