<?php

namespace Tests\Unit\Domain\EmailSecurity\Checks\DMARC;

use App\Domain\EmailSecurity\Checks\DMARC\Recommendations\DmarcRecommendationEvaluator;
use App\Models\Domain;
use Tests\Support\EmailSecurity\DmarcFixtureBuilder;
use Tests\TestCase;

class DmarcRecommendationEvaluatorTest extends TestCase
{
    private DmarcRecommendationEvaluator $evaluator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->evaluator = new DmarcRecommendationEvaluator();
    }

    public function test_missing_dmarc_recommendation(): void
    {
        $domain = new Domain([
            'domain' => 'missing.test',
            'dmarc_rua_email' => 'dmarc@missing.test',
        ]);
        $items = $this->evaluator->evaluate($domain, ['state' => 'missing'], null);

        $this->assertSame('dmarc_missing', $items[0]['legacy_key'] ?? null);
    }

    public function test_strengthen_recommendation_for_none_policy(): void
    {
        $domain = new Domain([
            'domain' => 'none.test',
            'dmarc_rua_email' => 'dmarc@none.test',
        ]);
        $analysis = DmarcFixtureBuilder::nativeAnalysis([
            'policy' => [
                'effective_policy' => 'none',
                'enforcement' => 'monitoring',
                'pct' => 100,
                'testing_mode' => false,
            ],
        ]);
        $dmarc = ['analysis' => $analysis, 'ui_state' => 'warning'];

        $items = $this->evaluator->evaluate($domain, ['state' => 'warning'], $dmarc);
        $keys = array_column($items, 'legacy_key');

        $this->assertContains('dmarc_policy', $keys);
    }

    public function test_mxscan_rua_recommendation_when_absent(): void
    {
        $domain = new Domain([
            'domain' => 'mxscan.test',
            'dmarc_rua_email' => 'dmarc+token@mxscan.me',
        ]);
        $analysis = DmarcFixtureBuilder::nativeAnalysis([
            'aggregate_reporting' => [
                'configured' => true,
                'destinations' => [[
                    'normalized_destination' => 'other@example.com',
                    'destination_domain' => 'example.com',
                ]],
                'mxscan_expectation' => [
                    'expected_address' => 'dmarc+token@mxscan.me',
                    'present' => false,
                    'other_valid_destination_exists' => true,
                ],
            ],
        ]);
        $dmarc = ['analysis' => $analysis, 'ui_state' => 'pass'];

        $items = $this->evaluator->evaluate($domain, ['state' => 'pass'], $dmarc);
        $keys = array_column($items, 'legacy_key');

        $this->assertContains('dmarc_mxscan_rua', $keys);
    }

    public function test_unauthorized_external_rua_recommendation(): void
    {
        $domain = new Domain([
            'domain' => 'external.test',
            'dmarc_rua_email' => 'dmarc@external.test',
        ]);
        $analysis = DmarcFixtureBuilder::nativeAnalysis([
            'aggregate_reporting' => [
                'configured' => true,
                'destinations' => [[
                    'normalized_destination' => 'reports@external.com',
                    'destination_domain' => 'external.com',
                    'authorization_status' => 'unauthorized',
                ]],
                'mxscan_expectation' => [
                    'expected_address' => null,
                    'present' => false,
                    'other_valid_destination_exists' => true,
                ],
            ],
        ]);
        $dmarc = ['analysis' => $analysis, 'ui_state' => 'warning'];

        $items = $this->evaluator->evaluate($domain, ['state' => 'warning'], $dmarc);
        $keys = array_column($items, 'legacy_key');

        $this->assertContains('dmarc_rua_unauthorized', $keys);
    }
}
