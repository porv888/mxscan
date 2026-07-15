<?php

namespace App\Providers;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck;
use App\Domain\EmailSecurity\Checks\BundledDnsChecksAdapter;
use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Checks\SpfAnalysisCheck;
use App\Domain\EmailSecurity\Checks\SPF\Compatibility\SpfLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator;
use App\Domain\EmailSecurity\Checks\SPF\Evidence\SpfEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\SPF\Evidence\SpfStatusDeriver;
use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAnalyzer;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParser;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicyResolver;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidator;
use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\Contracts\RecommendationEngineInterface;
use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\Contracts\ScanResultNormalizerInterface;
use App\Domain\EmailSecurity\Contracts\ScoreCalculatorInterface;
use App\Domain\EmailSecurity\DNS\LegacyScannerServiceAdapter;
use App\Domain\EmailSecurity\Recommendations\RecommendationCollectionGuard;
use App\Domain\EmailSecurity\Recommendations\RecommendationEngine;
use App\Domain\EmailSecurity\Reporting\ReportingService;
use App\Domain\EmailSecurity\Reporting\ScanReportFactory;
use App\Domain\EmailSecurity\Reporting\ScanResultNormalizer;
use App\Domain\EmailSecurity\Scoring\Rules\DkimScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\DmarcScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\MxScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\MtaStsScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\TlsRptScoreRule;
use App\Domain\EmailSecurity\Scoring\Rules\SpfScoreRule;
use App\Domain\EmailSecurity\Scoring\ScoreInvariantGuard;
use App\Domain\EmailSecurity\Scoring\LegacyDnsScoreCalculator;
use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\Compatibility\DkimLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\DKIM\Compatibility\DkimNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\DKIM\DkimAnalysisService;
use App\Domain\EmailSecurity\Checks\DKIM\DkimCheck;
use App\Domain\EmailSecurity\Checks\DKIM\Discovery\DkimRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsResolver;
use App\Domain\EmailSecurity\Checks\DKIM\Evidence\DkimEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\DKIM\Evidence\DkimStatusDeriver;
use App\Domain\EmailSecurity\Checks\DKIM\Inspection\DkimPublicKeyInspector;
use App\Domain\EmailSecurity\Checks\DKIM\Parsing\DkimRecordParser;
use App\Domain\EmailSecurity\Checks\DKIM\Recommendations\DkimRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\DKIM\DkimConfirmedSelectorRepository;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProviderSelectorResolver;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorNormalizer;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorSourceCollector;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSignatureSelectorExtractor;
use App\Domain\EmailSecurity\Checks\DKIM\Validation\DkimRecordValidator;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck;
use App\Domain\EmailSecurity\Checks\DMARC\Compatibility\DmarcLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\DMARC\Compatibility\DmarcNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcOrganizationalDomainResolver;
use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcRecordDiscovery;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcExternalDestinationValidator;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcReportingEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Evidence\DmarcEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\DMARC\Evidence\DmarcStatusDeriver;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\Checks\DMARC\Reporting\DmarcMxscanRuaExpectations;
use App\Domain\EmailSecurity\Checks\DMARC\Recommendations\DmarcRecommendationEvaluator;
use App\Services\Dmarc\DmarcRuaClassifier;
use App\Services\Dmarc\DmarcStatusService;
use App\Domain\EmailSecurity\Checks\SPF\SpfCheck;
use App\Domain\EmailSecurity\Support\ScanPersister;
use App\Domain\EmailSecurity\Support\ScanResultAssembler;
use App\Domain\EmailSecurity\Support\ScoringInputFactory;
use App\Domain\EmailSecurity\Checks\MtaSts\Compatibility\MtaStsLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\MtaSts\Compatibility\MtaStsNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsHttpClientInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Discovery\MtaStsDnsRecordDiscovery;
use App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsDependencyResolver;
use App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsHttpClient;
use App\Domain\EmailSecurity\Checks\MtaSts\Evidence\MtaStsEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\MtaSts\Evidence\MtaStsStatusDeriver;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetcher;
use App\Domain\EmailSecurity\Checks\MtaSts\Matching\MtaStsMxMatcher;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsAnalysisService;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsCheck;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsDnsRecordParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsPolicyParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Recommendations\MtaStsRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsDnsRecordValidator;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidator;
use App\Domain\EmailSecurity\Checks\TlsRpt\Compatibility\TlsRptLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\TlsRpt\Compatibility\TlsRptNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\TlsRpt\Discovery\TlsRptRecordDiscovery;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation\TlsRptDnsResolver;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evidence\TlsRptEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evidence\TlsRptStatusDeriver;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptDestinationParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptRecordParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Recommendations\TlsRptRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\TlsRpt\Reporting\TlsRptMxscanRuaExpectations;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptAnalysisService;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptCheck;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptDestinationValidator;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptRecordValidator;
use App\Domain\EmailSecurity\Checks\Mx\Compatibility\MxLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\Mx\Compatibility\MxNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxEvidenceProviderInterface;
use App\Domain\EmailSecurity\Checks\Mx\Discovery\MxRecordDiscovery;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxAddressClassifier;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsResolver;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxImplicitFallbackEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxNullPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordValidator;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxTargetResolver;
use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxEvidenceProvider;
use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxStatusDeriver;
use App\Domain\EmailSecurity\Checks\Mx\MxAnalysisService;
use App\Domain\EmailSecurity\Checks\Mx\MxCheck;
use App\Domain\EmailSecurity\Checks\Mx\Recommendations\MxRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateAnalysisService;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateCheck;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpointCollector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateEvidenceProvider;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateChainValidator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateHostnameValidator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateHttpsProbe;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateKeyInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateParser;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateProbeCoordinator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateSignatureInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateSmtpEvidenceAdapter;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateValidityEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;
use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateTrustStoreInterface;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateClock;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateMtaStsCompatMapper;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateRiskEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStatusDeriver;
use App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\Certificates\Monitoring\CertificateAlertEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\Monitoring\CertificateMonitoringService;
use App\Domain\EmailSecurity\Checks\Certificates\Monitoring\CertificateRenewalDetector;
use App\Domain\EmailSecurity\Checks\Certificates\Recommendations\CertificateRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\Scoring\CertificateScoreRule;
use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisService;
use App\Domain\EmailSecurity\Checks\Bimi\BimiAssertionDiscovery;
use App\Domain\EmailSecurity\Checks\Bimi\BimiCheck;
use App\Domain\EmailSecurity\Checks\Bimi\BimiDmarcEligibilityEvaluator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiEvidenceBuilder;
use App\Domain\EmailSecurity\Checks\Bimi\BimiEvidenceDocumentFetcher;
use App\Domain\EmailSecurity\Checks\Bimi\BimiIndicatorComparator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiIndicatorFetcher;
use App\Domain\EmailSecurity\Checks\Bimi\BimiMarkCertificateParser;
use App\Domain\EmailSecurity\Checks\Bimi\BimiMarkCertificateValidator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiProviderReadinessEvaluator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiRecordParser;
use App\Domain\EmailSecurity\Checks\Bimi\BimiRecordValidator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiRecommendationEvaluator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiSelectorResolver;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStatusDeriver;
use App\Domain\EmailSecurity\Checks\Bimi\BimiSvgValidator;
use App\Domain\EmailSecurity\Checks\Bimi\BimiSvgzDecompressor;
use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiClockInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiHttpClientInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiPublicSuffixInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiTrustStoreInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Infrastructure\BimiDnsResolver;
use App\Domain\EmailSecurity\Checks\Bimi\Infrastructure\BimiHardenedHttpClient;
use App\Domain\EmailSecurity\Checks\Bimi\Infrastructure\BimiPublicSuffixResolver;
use App\Domain\EmailSecurity\Checks\Bimi\Infrastructure\BimiSystemClock;
use App\Domain\EmailSecurity\Checks\Bimi\Infrastructure\BimiSystemTrustStore;
use App\Domain\EmailSecurity\Checks\Bimi\Monitoring\BimiAlertEvaluator;
use App\Domain\EmailSecurity\Checks\Bimi\Monitoring\BimiChangeDetector;
use App\Domain\EmailSecurity\Checks\Bimi\Monitoring\BimiMonitoringService;
use App\Domain\EmailSecurity\Checks\Bimi\Scoring\BimiScoreRule;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiIndicatorPreviewStore;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiLogoRasterizer;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiPublicPrivacyFilter;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiSecureXmlParser;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiUriValidator;
use App\Services\EmailSecurityScanService;
use Illuminate\Support\ServiceProvider;

class EmailSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(RecommendationCollectionGuard::class);
        $this->app->singleton(ScanResultAssembler::class);
        $this->app->singleton(SpfAnalysisCheck::class);
        $this->app->singleton(BundledDnsChecksAdapter::class);
        $this->app->singleton(ScoringInputFactory::class);
        $this->app->singleton(ScanResultNormalizer::class);

        $this->registerNativeSpfServices();

        $this->registerNativeDmarcServices();

        $this->registerNativeDkimServices();

        $this->registerNativeMxServices();

        $this->registerNativeCertificateServices();

        $this->registerNativeMtaStsServices();

        $this->registerNativeTlsRptServices();

        $this->registerNativeBimiServices();

        $this->registerNativeBlacklistServices();

        $this->app->singleton(CheckRegistry::class, function ($app) {
            return new CheckRegistry([
                $this->resolveSpfCheck($app),
                $app->make(DmarcCheck::class),
                $app->make(DkimCheck::class),
                $app->make(MxCheck::class),
                $app->make(MtaStsCheck::class),
                $app->make(TlsRptCheck::class),
                $app->make(BimiCheck::class),
                $app->make(BlacklistCheck::class),
                $app->make(CertificateCheck::class),
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

    private function registerNativeSpfServices(): void
    {
        $this->app->singleton(SpfDnsDependencyResolver::class);
        $this->app->singleton(SpfRecordDiscovery::class);
        $this->app->singleton(SpfParser::class);
        $this->app->singleton(SpfValidator::class);
        $this->app->singleton(SpfMacroAnalyzer::class);
        $this->app->singleton(SpfStatusDeriver::class);
        $this->app->singleton(SpfTerminalPolicyResolver::class);
        $this->app->singleton(SpfEvaluator::class);
        $this->app->singleton(SpfEvidenceBuilder::class);
        $this->app->singleton(SpfLegacyPayloadAdapter::class);
        $this->app->singleton(SpfCheck::class);
        $this->app->singleton(SpfScoreRule::class);
        $this->app->singleton(ScoreInvariantGuard::class);
    }

    private function registerNativeDmarcServices(): void
    {
        $this->app->singleton(DmarcDnsResolverInterface::class, DmarcDnsDependencyResolver::class);
        $this->app->singleton(DmarcDnsDependencyResolver::class);
        $this->app->singleton(DmarcRecordDiscovery::class);
        $this->app->singleton(DmarcParser::class);
        $this->app->singleton(DmarcValidator::class);
        $this->app->singleton(DmarcPolicyEvaluator::class);
        $this->app->singleton(DmarcReportingEvaluator::class);
        $this->app->singleton(DmarcExternalDestinationValidator::class);
        $this->app->singleton(DmarcMxscanRuaExpectations::class);
        $this->app->singleton(DmarcStatusDeriver::class);
        $this->app->singleton(DmarcEvidenceBuilder::class);
        $this->app->singleton(DmarcNativeAnalysisPayload::class);
        $this->app->singleton(DmarcLegacyPayloadAdapter::class);
        $this->app->singleton(DmarcOrganizationalDomainResolver::class);
        $this->app->singleton(DmarcCheck::class);
        $this->app->singleton(DmarcScoreRule::class);
        $this->app->singleton(DmarcRecommendationEvaluator::class);
        $this->app->singleton(DmarcRuaClassifier::class);
        $this->app->singleton(DmarcStatusService::class);
    }

    private function registerNativeDkimServices(): void
    {
        $this->app->singleton(DkimDnsResolverInterface::class, DkimDnsResolver::class);
        $this->app->singleton(DkimDnsResolver::class);
        $this->app->singleton(DkimSelectorNormalizer::class);
        $this->app->singleton(DkimSignatureSelectorExtractor::class);
        $this->app->singleton(DkimConfirmedSelectorRepository::class);
        $this->app->singleton(DkimProviderSelectorResolver::class);
        $this->app->singleton(DkimSelectorSourceCollector::class);
        $this->app->singleton(DkimRecordDiscovery::class);
        $this->app->singleton(DkimRecordParser::class);
        $this->app->singleton(DkimPublicKeyInspector::class);
        $this->app->singleton(DkimRecordValidator::class);
        $this->app->singleton(DkimStatusDeriver::class);
        $this->app->singleton(DkimEvidenceBuilder::class);
        $this->app->singleton(DkimNativeAnalysisPayload::class);
        $this->app->singleton(DkimLegacyPayloadAdapter::class);
        $this->app->singleton(DkimAnalysisService::class);
        $this->app->singleton(DkimCheck::class);
        $this->app->singleton(DkimScoreRule::class);
        $this->app->singleton(DkimRecommendationEvaluator::class);
    }

    private function registerNativeMxServices(): void
    {
        $this->app->bind(MxDnsResolverInterface::class, MxDnsResolver::class);
        $this->app->bind(MxDnsResolver::class, MxDnsResolver::class);
        $this->app->singleton(MxRecordNormalizer::class);
        $this->app->singleton(MxRecordDiscovery::class);
        $this->app->singleton(MxRecordValidator::class);
        $this->app->singleton(MxNullPolicyEvaluator::class);
        $this->app->singleton(MxAddressClassifier::class);
        $this->app->singleton(MxImplicitFallbackEvaluator::class);
        $this->app->singleton(MxTargetResolver::class);
        $this->app->singleton(MxStatusDeriver::class);
        $this->app->singleton(MxEvidenceBuilder::class);
        $this->app->singleton(MxNativeAnalysisPayload::class);
        $this->app->singleton(MxLegacyPayloadAdapter::class);
        $this->app->singleton(MxAnalysisService::class);
        $this->app->singleton(MxCheck::class);
        $this->app->singleton(MxScoreRule::class);
        $this->app->singleton(MxRecommendationEvaluator::class);
    }

    private function registerNativeMtaStsServices(): void
    {
        $this->app->singleton(MtaStsDnsResolverInterface::class, MtaStsDnsDependencyResolver::class);
        $this->app->singleton(MtaStsDnsDependencyResolver::class);
        $this->app->singleton(MtaStsDnsRecordDiscovery::class);
        $this->app->singleton(MtaStsDnsRecordParser::class);
        $this->app->singleton(MtaStsDnsRecordValidator::class);
        $this->app->singleton(MtaStsHttpClientInterface::class, MtaStsHttpClient::class);
        $this->app->singleton(MtaStsHttpClient::class);
        $this->app->singleton(MtaStsPolicyFetcher::class);
        $this->app->singleton(MtaStsPolicyParser::class);
        $this->app->singleton(MtaStsPolicyValidator::class);
        $this->app->singleton(CertificateMtaStsCompatMapper::class);
        $this->app->singleton(MxEvidenceProviderInterface::class, MxEvidenceProvider::class);
        $this->app->singleton(MxEvidenceProvider::class);
        $this->app->singleton(MtaStsMxMatcher::class);
        $this->app->singleton(MtaStsStatusDeriver::class);
        $this->app->singleton(MtaStsEvidenceBuilder::class);
        $this->app->singleton(MtaStsNativeAnalysisPayload::class);
        $this->app->singleton(MtaStsLegacyPayloadAdapter::class);
        $this->app->singleton(MtaStsAnalysisService::class);
        $this->app->singleton(MtaStsCheck::class);
        $this->app->singleton(MtaStsScoreRule::class);
        $this->app->singleton(MtaStsRecommendationEvaluator::class);
    }

    private function registerNativeTlsRptServices(): void
    {
        $this->app->singleton(TlsRptDnsResolverInterface::class, TlsRptDnsResolver::class);
        $this->app->singleton(TlsRptDnsResolver::class);
        $this->app->singleton(TlsRptRecordDiscovery::class);
        $this->app->singleton(TlsRptRecordParser::class);
        $this->app->singleton(TlsRptRecordValidator::class);
        $this->app->singleton(TlsRptDestinationParser::class);
        $this->app->singleton(TlsRptDestinationValidator::class);
        $this->app->singleton(TlsRptMxscanRuaExpectations::class);
        $this->app->singleton(TlsRptStatusDeriver::class);
        $this->app->singleton(TlsRptEvidenceBuilder::class);
        $this->app->singleton(TlsRptNativeAnalysisPayload::class);
        $this->app->singleton(TlsRptLegacyPayloadAdapter::class);
        $this->app->singleton(TlsRptAnalysisService::class);
        $this->app->singleton(TlsRptCheck::class);
        $this->app->singleton(TlsRptScoreRule::class);
        $this->app->singleton(TlsRptRecommendationEvaluator::class);
    }

    private function registerNativeBimiServices(): void
    {
        $this->app->singleton(BimiDnsResolverInterface::class, BimiDnsResolver::class);
        $this->app->singleton(BimiDnsResolver::class);
        $this->app->singleton(BimiHttpClientInterface::class, BimiHardenedHttpClient::class);
        $this->app->singleton(BimiHardenedHttpClient::class);
        $this->app->singleton(BimiTrustStoreInterface::class, BimiSystemTrustStore::class);
        $this->app->singleton(BimiSystemTrustStore::class);
        $this->app->singleton(BimiClockInterface::class, BimiSystemClock::class);
        $this->app->singleton(BimiSystemClock::class);
        $this->app->singleton(BimiPublicSuffixInterface::class, BimiPublicSuffixResolver::class);
        $this->app->singleton(BimiPublicSuffixResolver::class);
        $this->app->singleton(BimiUriValidator::class);
        $this->app->singleton(BimiSecureXmlParser::class);
        $this->app->singleton(BimiSelectorResolver::class);
        $this->app->singleton(BimiAssertionDiscovery::class);
        $this->app->singleton(BimiRecordParser::class);
        $this->app->singleton(BimiRecordValidator::class);
        $this->app->singleton(BimiSvgzDecompressor::class);
        $this->app->singleton(BimiSvgValidator::class);
        $this->app->singleton(BimiIndicatorFetcher::class);
        $this->app->singleton(BimiEvidenceDocumentFetcher::class);
        $this->app->singleton(BimiMarkCertificateParser::class);
        $this->app->singleton(BimiMarkCertificateValidator::class);
        $this->app->singleton(BimiIndicatorComparator::class);
        $this->app->singleton(BimiDmarcEligibilityEvaluator::class);
        $this->app->singleton(BimiProviderReadinessEvaluator::class);
        $this->app->singleton(BimiStatusDeriver::class);
        $this->app->singleton(BimiEvidenceBuilder::class);
        $this->app->singleton(BimiNativeAnalysisPayload::class);
        $this->app->singleton(BimiLegacyPayloadAdapter::class);
        $this->app->singleton(BimiAnalysisService::class);
        $this->app->singleton(BimiCheck::class);
        $this->app->singleton(BimiScoreRule::class);
        $this->app->singleton(BimiRecommendationEvaluator::class);
        $this->app->singleton(BimiChangeDetector::class);
        $this->app->singleton(BimiAlertEvaluator::class);
        $this->app->singleton(BimiMonitoringService::class);
        $this->app->singleton(BimiIndicatorPreviewStore::class);
        $this->app->singleton(BimiLogoRasterizer::class);
        $this->app->singleton(BimiPublicPrivacyFilter::class);
    }

    private function registerNativeBlacklistServices(): void
    {
        $this->app->bind(
            \App\Domain\EmailSecurity\Checks\Blacklist\Contracts\BlacklistDnsResolverInterface::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsResolver::class,
        );
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsResolver::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistProviderRegistry::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv4QueryBuilder::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistIpv6QueryBuilder::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistResponseInterpreter::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistTargetCollector::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistEvidenceBuilder::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistStatusDeriver::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Compatibility\BlacklistNativeAnalysisPayload::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Compatibility\BlacklistLegacyPayloadAdapter::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Persistence\BlacklistResultWriter::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistAnalysisService::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class);
        $this->app->singleton(\App\Domain\EmailSecurity\Checks\Blacklist\Recommendations\BlacklistRecommendationEvaluator::class);
    }

    private function registerNativeCertificateServices(): void
    {
        $this->app->scoped(CertificateProbeCoordinator::class);
        $this->app->singleton(CertificateClockInterface::class, SystemCertificateClock::class);
        $this->app->singleton(CertificateTrustStoreInterface::class, SystemCertificateTrustStore::class);
        $this->app->singleton(SystemCertificateClock::class);
        $this->app->singleton(SystemCertificateTrustStore::class);
        $this->app->singleton(CertificateParser::class);
        $this->app->singleton(CertificateHostnameValidator::class);
        $this->app->singleton(CertificateValidityEvaluator::class);
        $this->app->singleton(CertificateChainValidator::class);
        $this->app->singleton(CertificateKeyInspector::class);
        $this->app->singleton(CertificateSignatureInspector::class);
        $this->app->singleton(CertificateHttpsProbe::class);
        $this->app->singleton(CertificateSmtpEvidenceAdapter::class);
        $this->app->singleton(CertificateMtaStsCompatMapper::class);
        $this->app->singleton(CertificateStatusDeriver::class);
        $this->app->singleton(CertificateEvidenceBuilder::class);
        $this->app->singleton(CertificateNativeAnalysisPayload::class);
        $this->app->singleton(CertificateLegacyPayloadAdapter::class);
        $this->app->singleton(CertificateAnalysisService::class);
        $this->app->singleton(CertificateRiskEvaluator::class);
        $this->app->singleton(CertificateRenewalDetector::class);
        $this->app->singleton(CertificateAlertEvaluator::class);
        $this->app->singleton(CertificateMonitoringService::class);
        $this->app->singleton(CertificateRecommendationEvaluator::class);
        $this->app->singleton(CertificateScoreRule::class);
        $this->app->singleton(CertificateCheck::class);
        $this->app->singleton(CertificateEndpointCollector::class);
        $this->app->singleton(CertificateEvidenceProvider::class, function ($app) {
            return new CertificateEvidenceProvider(
                $app->make(CertificateEndpointCollector::class),
                $app->make(CertificateProbeCoordinator::class),
                $app->make(CertificateParser::class),
                $app->make(CertificateHostnameValidator::class),
                $app->make(CertificateValidityEvaluator::class),
                $app->make(CertificateChainValidator::class),
                $app->make(CertificateKeyInspector::class),
                $app->make(CertificateSignatureInspector::class),
                probes: [
                    $app->make(CertificateHttpsProbe::class),
                    $app->make(CertificateSmtpEvidenceAdapter::class),
                ],
                evidenceProviders: [],
            );
        });
    }

    private function resolveSpfCheck($app): SpfCheck|SpfAnalysisCheck
    {
        return match (config('email-security.spf_engine', 'legacy')) {
            'native' => $app->make(SpfCheck::class),
            default => $app->make(SpfAnalysisCheck::class),
        };
    }
}
