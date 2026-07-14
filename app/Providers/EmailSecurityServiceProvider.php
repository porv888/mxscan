<?php

namespace App\Providers;

use App\Domain\EmailSecurity\Checks\BlacklistCheck;
use App\Domain\EmailSecurity\Checks\BundledDnsChecksAdapter;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Checks\SpfAnalysisCheck;
use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\Contracts\RecommendationEngineInterface;
use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Contracts\ScanResultNormalizerInterface;
use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DNS\LegacyScannerServiceAdapter;
use App\Domain\EmailSecurity\Recommendations\RecommendationEngine;
use App\Domain\EmailSecurity\Reporting\ReportingService;
use App\Domain\EmailSecurity\Reporting\ScanReportFactory;
use App\Domain\EmailSecurity\Reporting\ScanResultNormalizer;
use App\Domain\EmailSecurity\Scoring\LegacyDnsScoreCalculator;
use App\Domain\EmailSecurity\Support\ScanPersister;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Support\ScoringInputFactory;
use App\Services\EmailSecurityScanService;
use Illuminate\Support\ServiceProvider;

class EmailSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScanResultAssembler::class);
        $this->app->singleton(SpfAnalysisCheck::class);
        $this->app->singleton(BlacklistCheck::class);
        $this->app->singleton(BundledDnsChecksAdapter::class);
        $this->app->singleton(ScoringInputFactory::class);
        $this->app->singleton(ScanResultNormalizer::class);

        $this->app->singleton(CheckRegistry::class, function ($app) {
            return new CheckRegistry([
                $app->make(SpfAnalysisCheck::class),
                $app->make(BlacklistCheck::class),
            ]);
        });

        $this->app->bind(DnsCollectorInterface::class, LegacyScannerServiceAdapter::class);
        $this->app->bind(ScoreCalculatorInterface::class, LegacyDnsScoreCalculator::class);
        $this->app->bind(RecommendationEngineInterface::class, RecommendationEngine::class);
        $this->app->bind(ScanResultNormalizerInterface::class, ScanResultNormalizer::class);
        $this->app->bind(ScanPersisterInterface::class, ScanPersister::class);
        $this->app->bind(ScanReportFactoryInterface::class, ScanReportFactory::class);
        $this->app->bind(EmailSecurityScanService::class);
    }
}
