<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEvidenceProvider;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpointCollector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateParser;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateHostnameValidator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateValidityEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateChainValidator;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateKeyInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateSignatureInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateProbeCoordinator;
use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;

final class CertificateTestProbeFactory
{
    public static function bindFakeProbes(): void
    {
        app()->singleton(CertificateClockInterface::class, FakeCertificateClock::class);
        app()->singleton(CertificateChainValidator::class, PermissiveCertificateChainValidator::class);
        app()->singleton(CertificateEvidenceProvider::class, function ($app) {
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
                    new FakeCertificateHttpsProbe(),
                    new FakeCertificateSmtpProbe(),
                ],
                evidenceProviders: [],
            );
        });
    }
}
