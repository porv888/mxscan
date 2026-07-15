<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Checks\DKIM\Evidence\DkimStatusDeriver;
use PHPUnit\Framework\TestCase;

class DkimStatusDeriverTest extends TestCase
{
    public function test_domain_state_uses_valid_selectors_not_catalog_misses(): void
    {
        $deriver = new DkimStatusDeriver();

        $result = $deriver->deriveDomain([
            [
                'selector' => 'google',
                'record_status' => 'none',
                'risk_status' => 'critical',
                'state' => DkimStates::MISSING,
            ],
            [
                'selector' => 'default',
                'record_status' => 'valid',
                'risk_status' => 'healthy',
                'state' => DkimStates::PASS,
            ],
        ], [
            'selectors_available' => true,
            'coverage_type' => 'catalog_only',
        ]);

        $this->assertSame(DkimStates::PASS, $result['state']);
        $this->assertStringContainsString('selector default', $result['summary']);
    }
}
