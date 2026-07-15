<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\Scoring\Rules\DmarcScoreRule;
use Tests\TestCase;

class DmarcScoreRuleTest extends TestCase
{
    public function test_reject_full_enforcement_scores_thirty(): void
    {
        $native = $this->native([
            'protocolStatus' => DmarcProtocolStatus::VALID,
            'policy' => [
                'effective_policy' => 'reject',
                'enforcement' => 'reject',
                'pct' => 100,
                'testing_mode' => false,
            ],
        ]);

        $component = (new DmarcScoreRule())->score($native);

        $this->assertSame(30, $component->earned);
        $this->assertSame('dmarc-v1', $component->modelVersion);
    }

    public function test_missing_scores_zero(): void
    {
        $native = $this->native([
            'protocolStatus' => DmarcProtocolStatus::NONE,
            'policy' => [],
        ]);

        $component = (new DmarcScoreRule())->score($native);

        $this->assertSame(0, $component->earned);
    }

    public function test_quarantine_scores_twenty_four(): void
    {
        $native = $this->native([
            'protocolStatus' => DmarcProtocolStatus::VALID,
            'policy' => [
                'effective_policy' => 'quarantine',
                'enforcement' => 'quarantine',
                'pct' => 100,
                'testing_mode' => false,
            ],
        ]);

        $this->assertSame(24, (new DmarcScoreRule())->score($native)->earned);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function native(array $overrides): DmarcNativeResult
    {
        return new DmarcNativeResult(
            state: $overrides['state'] ?? 'pass',
            protocolStatus: $overrides['protocolStatus'],
            riskStatus: $overrides['riskStatus'] ?? 'healthy',
            summary: $overrides['summary'] ?? 'summary',
            rawRecord: $overrides['rawRecord'] ?? 'v=DMARC1; p=reject',
            recordDomain: '_dmarc.example.test',
            policyDomain: 'example.test',
            policySource: 'exact',
            organizationalDomain: 'example.test',
            discovery: [],
            policy: $overrides['policy'],
            alignment: ['dkim' => 'relaxed', 'spf' => 'relaxed'],
            aggregateReporting: ['configured' => false, 'destinations' => []],
            failureReporting: ['configured' => false, 'destinations' => []],
            externalAuthorization: ['destinations_checked' => 0, 'unauthorized_count' => 0],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );
    }
}
