<?php

namespace Tests\Unit\Domain\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisService;
use App\Domain\EmailSecurity\Checks\Bimi\BimiRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStatusDeriver;
use App\Domain\EmailSecurity\Checks\Bimi\Scoring\BimiScoreRule;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;
use Tests\TestCase;

class BimiArchitectureTest extends TestCase
{
    public function test_bimi_score_rule_is_zero_weight(): void
    {
        $rule = app(BimiScoreRule::class);
        $component = $rule->score(new \App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult(
            state: 'missing',
            protocolStatus: 'none',
            readinessStatus: 'not_ready',
            evidenceStatus: 'absent',
            riskStatus: 'informational',
            summary: 'No BIMI record.',
            domain: 'example.test',
            recordHostname: 'default._bimi.example.test',
            evaluationCompleteness: 'complete',
        ));

        $this->assertInstanceOf(ScoreComponentDTO::class, $component);
        $this->assertSame(0, $component->earned);
        $this->assertSame(0, $component->possible);
        $this->assertSame('bimi-readiness-v1', $component->modelVersion);
    }

    public function test_check_registry_enables_bimi_with_dns_option(): void
    {
        $registry = app(CheckRegistry::class);
        $this->assertContains('bimi', $registry->keys());
    }

    public function test_bimi_analysis_service_is_singleton_entry(): void
    {
        $this->assertInstanceOf(BimiAnalysisService::class, app(BimiAnalysisService::class));
    }

    public function test_bimi_status_deriver_and_recommendation_evaluator_exist(): void
    {
        $this->assertInstanceOf(BimiStatusDeriver::class, app(BimiStatusDeriver::class));
        $this->assertInstanceOf(BimiRecommendationEvaluator::class, app(BimiRecommendationEvaluator::class));
    }

    public function test_bimi_views_do_not_embed_remote_svg(): void
    {
        $bimiCheck = (string) file_get_contents(resource_path('views/tools/bimi-check.blade.php'));
        $this->assertStringNotContainsString('<img', $bimiCheck);
        $this->assertStringNotContainsString('{!!', $bimiCheck);
    }
}
