<?php

namespace Tests\Unit;

use App\Services\EmailAuthEvaluator;
use App\Services\DkimVerifier;
use Tests\TestCase;

class EmailAuthEvaluatorTest extends TestCase
{
    protected EmailAuthEvaluator $evaluator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->evaluator = app(EmailAuthEvaluator::class);
    }

    /**
     * Test header parsing
     */
    public function test_parses_headers_correctly(): void
    {
        $headers = "From: sender@example.com\r\n";
        $headers .= "To: recipient@test.com\r\n";
        $headers .= "Subject: Test\r\n";
        $headers .= "Received: from mail.example.com ([192.0.2.1])\r\n";
        $headers .= "Return-Path: <envelope@example.com>\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('spf', $result);
        $this->assertArrayHasKey('dkim', $result);
        $this->assertArrayHasKey('dmarc', $result);
        $this->assertArrayHasKey('details', $result);
        $this->assertArrayHasKey('sources', $result);
    }

    /**
     * Test IP extraction from Received header
     */
    public function test_extracts_ip_from_received_header(): void
    {
        $headers = "Received: from mail.example.com ([192.0.2.1])\r\n";
        $headers .= "From: sender@example.com\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('192.0.2.1', $result['details']['ip']);
    }

    /**
     * Test IPv6 extraction
     */
    public function test_extracts_ipv6_from_received_header(): void
    {
        $headers = "Received: from mail.example.com ([IPv6:2001:db8::1])\r\n";
        $headers .= "From: sender@example.com\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('2001:db8::1', $result['details']['ip']);
    }

    /**
     * Test envelope-from extraction
     */
    public function test_extracts_envelope_from(): void
    {
        $headers = "Return-Path: <envelope@example.com>\r\n";
        $headers .= "From: sender@example.com\r\n";
        $headers .= "Received: from mail.example.com ([192.0.2.1])\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('envelope@example.com', $result['details']['mailfrom']);
        $this->assertEquals('example.com', $result['details']['mailfrom_domain']);
    }

    /**
     * Test header-from extraction
     */
    public function test_extracts_header_from(): void
    {
        $headers = "From: \"John Doe\" <sender@example.com>\r\n";
        $headers .= "Received: from mail.example.com ([192.0.2.1])\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('sender@example.com', $result['details']['header_from']);
        $this->assertEquals('example.com', $result['details']['header_from_domain']);
    }

    /**
     * Test SPF none when no IP
     */
    public function test_spf_none_when_no_ip(): void
    {
        $headers = "From: sender@example.com\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('none', $result['spf']);
        $this->assertStringContainsString('Unable to determine connecting IP', implode(' ', $result['details']['notes']));
    }

    /**
     * Test DKIM none when no body provided
     */
    public function test_dkim_none_when_no_body(): void
    {
        $headers = "From: sender@example.com\r\n";
        $headers .= "Received: from mail.example.com ([192.0.2.1])\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('none', $result['dkim']);
        $this->assertStringContainsString('Body not provided', implode(' ', $result['details']['notes']));
    }

    /**
     * Test sources are marked as 'app'
     */
    public function test_sources_marked_as_app(): void
    {
        $headers = "From: sender@example.com\r\n";
        $headers .= "Received: from mail.example.com ([192.0.2.1])\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('app', $result['sources']['spf']);
        $this->assertEquals('app', $result['sources']['dkim']);
        $this->assertEquals('app', $result['sources']['dmarc']);
    }

    /**
     * Test folded headers are handled
     */
    public function test_handles_folded_headers(): void
    {
        $headers = "From: sender@example.com\r\n";
        $headers .= "Received: from mail.example.com\r\n";
        $headers .= " ([192.0.2.1])\r\n";
        $headers .= " by mx.test.com\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        $this->assertEquals('192.0.2.1', $result['details']['ip']);
    }

    /**
     * Test multiple Received headers (uses topmost)
     */
    public function test_uses_topmost_received_header(): void
    {
        $headers = "Received: from first.example.com ([192.0.2.1])\r\n";
        $headers .= "Received: from second.example.com ([192.0.2.2])\r\n";
        $headers .= "From: sender@example.com\r\n";

        $result = $this->evaluator->evaluate($headers, null);

        // Should use the first (topmost) Received header
        $this->assertEquals('192.0.2.1', $result['details']['ip']);
    }
}
