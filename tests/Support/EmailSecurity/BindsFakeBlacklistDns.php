<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Blacklist\Contracts\BlacklistDnsResolverInterface;

trait BindsFakeBlacklistDns
{
    protected function bindFakeBlacklistDns(?FakeBlacklistDnsResolver $resolver = null): FakeBlacklistDnsResolver
    {
        $resolver ??= new FakeBlacklistDnsResolver();
        $this->app->instance(BlacklistDnsResolverInterface::class, $resolver);
        foreach ([
            \App\Domain\EmailSecurity\Checks\CheckRegistry::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsResolver::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistEvidenceBuilder::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistAnalysisService::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator::class,
            \App\Domain\EmailSecurity\Checks\Blacklist\BlacklistCheck::class,
        ] as $class) {
            $this->app->forgetInstance($class);
        }

        return $resolver;
    }
}
