<?php

namespace Tests\Support\EmailSecurity;

trait ResetsScanPipelineContainer
{
    protected function resetScanPipelineContainer(): void
    {
        foreach ([
            \App\Domain\EmailSecurity\Checks\CheckRegistry::class,
            \App\Domain\EmailSecurity\Contracts\DnsCollectorInterface::class,
            \App\Services\Dns\DnsClient::class,
            \App\Domain\EmailSecurity\Checks\SPF\SpfCheck::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluator::class,
            \App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver::class,
            \App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfRecordDiscovery::class,
            \App\Domain\EmailSecurity\Checks\DKIM\DkimCheck::class,
            \App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface::class,
            \App\Domain\EmailSecurity\Checks\DMARC\DmarcCheck::class,
            \App\Domain\EmailSecurity\Checks\Mx\MxCheck::class,
            \App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class,
            \App\Services\EmailSecurityScanService::class,
            \App\Services\ScanRunner::class,
        ] as $class) {
            $this->app->forgetInstance($class);
        }
    }
}
