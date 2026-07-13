<?php

namespace Tests\Unit;

use App\Services\Dmarc\DmarcRuaClassifier;
use PHPUnit\Framework\TestCase;

class DmarcRuaClassifierTest extends TestCase
{
    protected DmarcRuaClassifier $classifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->classifier = new DmarcRuaClassifier();
    }

    public function test_parses_comma_separated_mailtos_with_whitespace(): void
    {
        $recipients = $this->classifier->parseRuaRecipients(
            ' mailto:a@example.com , mailto:b@example.com '
        );

        $this->assertCount(2, $recipients);
        $this->assertSame('a@example.com', $recipients[0]['email']);
        $this->assertSame('b@example.com', $recipients[1]['email']);
    }

    public function test_case_insensitive_tags_and_mxscan_domain(): void
    {
        $record = 'v=DMARC1; P=none; RUA=MailTo:dmarc+abc@MXScan.ME';
        $classification = $this->classifier->classify($record, 'dmarc+abc@mxscan.me');

        $this->assertTrue($classification['has_canonical_mxscan_rua']);
        $this->assertSame(DmarcRuaClassifier::LINK_CONNECTED, $classification['rua_link_state']);
    }

    public function test_optional_size_suffix_is_supported(): void
    {
        $parsed = $this->classifier->parseMailtoUri('mailto:dmarc+tok@mxscan.me!10m');

        $this->assertNotNull($parsed);
        $this->assertSame('dmarc+tok@mxscan.me', $parsed['email']);
        $this->assertSame('10m', $parsed['size']);

        $classification = $this->classifier->classify(
            'v=DMARC1; p=none; rua=mailto:dmarc+tok@mxscan.me!10m',
            'dmarc+tok@mxscan.me'
        );

        $this->assertTrue($classification['has_canonical_mxscan_rua']);
        $this->assertTrue($classification['has_any_mxscan_rua']);
    }

    public function test_canonical_alone_is_connected(): void
    {
        $classification = $this->classifier->classify(
            'v=DMARC1; p=quarantine; rua=mailto:dmarc+newtoken@mxscan.me',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_CONNECTED, $classification['rua_link_state']);
        $this->assertTrue($classification['has_canonical_mxscan_rua']);
        $this->assertTrue($classification['has_any_mxscan_rua']);
    }

    public function test_generic_dmarc_at_mxscan_is_detected_unlinked(): void
    {
        $classification = $this->classifier->classify(
            'v=DMARC1; p=none; rua=mailto:dmarc@mxscan.me',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_DETECTED_UNLINKED, $classification['rua_link_state']);
        $this->assertTrue($classification['has_any_mxscan_rua']);
        $this->assertFalse($classification['has_canonical_mxscan_rua']);
    }

    public function test_stale_token_is_detected_unlinked(): void
    {
        $classification = $this->classifier->classify(
            'v=DMARC1; p=none; rua=mailto:dmarc+oldtoken@mxscan.me',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_DETECTED_UNLINKED, $classification['rua_link_state']);
    }

    public function test_external_only_is_not_connected(): void
    {
        $classification = $this->classifier->classify(
            'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_NOT_CONNECTED, $classification['rua_link_state']);
        $this->assertFalse($classification['has_any_mxscan_rua']);
    }

    public function test_missing_rua_is_not_connected(): void
    {
        $classification = $this->classifier->classify(
            'v=DMARC1; p=none',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_NOT_CONNECTED, $classification['rua_link_state']);
    }

    public function test_evil_mxscan_subdomain_is_not_mxscan(): void
    {
        $this->assertFalse($this->classifier->isMxscanEmail('user@evil-mxscan.me'));
        $this->assertFalse($this->classifier->isMxscanEmail('user@mxscan.me.evil.com'));

        $classification = $this->classifier->classify(
            'v=DMARC1; p=none; rua=mailto:user@evil-mxscan.me',
            'dmarc+newtoken@mxscan.me'
        );

        $this->assertSame(DmarcRuaClassifier::LINK_NOT_CONNECTED, $classification['rua_link_state']);
        $this->assertFalse($classification['has_any_mxscan_rua']);
    }

    public function test_required_rewrite_example_preserves_external_and_single_mxscan(): void
    {
        $input = 'v=DMARC1; p=quarantine; rua=mailto:dmarc@mxscan.me,mailto:dmarc+oldtoken@mxscan.me,mailto:rua@dmarc.brevo.com';
        $canonical = 'dmarc+newtoken@mxscan.me';

        $result = $this->classifier->rewriteRua($input, $canonical);

        $this->assertSame('relink_rua', $result['action']);
        $this->assertSame(
            'v=DMARC1; p=quarantine; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+newtoken@mxscan.me',
            $result['updated']
        );

        $updatedClass = $this->classifier->classify($result['updated'], $canonical);
        $this->assertCount(1, $updatedClass['mxscan_recipients']);
        $this->assertTrue($updatedClass['has_canonical_mxscan_rua']);
    }

    public function test_rewrite_preserves_unrelated_tags(): void
    {
        $input = 'v=DMARC1; p=reject; sp=none; pct=100; adkim=s; aspf=s; rua=mailto:dmarc+old@mxscan.me';
        $result = $this->classifier->rewriteRua($input, 'dmarc+new@mxscan.me');

        $this->assertStringContainsString('p=reject', $result['updated']);
        $this->assertStringContainsString('sp=none', $result['updated']);
        $this->assertStringContainsString('pct=100', $result['updated']);
        $this->assertStringContainsString('adkim=s', $result['updated']);
        $this->assertStringContainsString('aspf=s', $result['updated']);
        $this->assertStringContainsString('mailto:dmarc+new@mxscan.me', $result['updated']);
        $this->assertStringNotContainsString('dmarc+old@mxscan.me', $result['updated']);
    }

    public function test_canonical_alone_rewrite_is_none(): void
    {
        $record = 'v=DMARC1; p=none; rua=mailto:dmarc+newtoken@mxscan.me';
        $result = $this->classifier->rewriteRua($record, 'dmarc+newtoken@mxscan.me');

        $this->assertSame('none', $result['action']);
        $this->assertSame($record, $result['updated']);
        $this->assertTrue($result['mxscan_already_present']);
    }

    public function test_external_only_rewrite_appends(): void
    {
        $input = 'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com';
        $result = $this->classifier->rewriteRua($input, 'dmarc+newtoken@mxscan.me');

        $this->assertSame('append_rua', $result['action']);
        $this->assertSame(
            'v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com,mailto:dmarc+newtoken@mxscan.me',
            $result['updated']
        );
    }

    public function test_canonical_plus_duplicate_mxscan_relinks_to_one(): void
    {
        $input = 'v=DMARC1; p=none; rua=mailto:dmarc+newtoken@mxscan.me,mailto:dmarc@mxscan.me,mailto:rua@dmarc.brevo.com';
        $result = $this->classifier->rewriteRua($input, 'dmarc+newtoken@mxscan.me');

        $this->assertSame('relink_rua', $result['action']);
        $classification = $this->classifier->classify($result['updated'], 'dmarc+newtoken@mxscan.me');
        $this->assertCount(1, $classification['mxscan_recipients']);
        $this->assertTrue($classification['has_canonical_mxscan_rua']);
        $this->assertStringContainsString('mailto:rua@dmarc.brevo.com', $result['updated']);
    }
}
