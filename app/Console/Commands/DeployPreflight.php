<?php

namespace App\Console\Commands;

use App\Domain\EmailSecurity\Checks\CheckRegistry;
use App\Domain\EmailSecurity\Checks\SPF\SpfCheck;
use Illuminate\Console\Command;

class DeployPreflight extends Command
{
    protected $signature = 'deploy:preflight';

    protected $description = 'Verify production deployment prerequisites before going live';

    public function handle(): int
    {
        $failures = [];

        if (config()->has('email-security.spf_engine')) {
            $failures[] = 'email-security.spf_engine config must be removed (native SPF is mandatory)';
        }

        $registry = app(CheckRegistry::class);
        if (!in_array('spf', $registry->keys(), true)) {
            $failures[] = 'CheckRegistry is missing the spf check';
        }

        if (!app()->make(SpfCheck::class) instanceof SpfCheck) {
            $failures[] = 'SpfCheck is not bound in the container';
        }

        if (is_file(app_path('Domain/EmailSecurity/Checks/SpfAnalysisCheck.php'))) {
            $failures[] = 'Legacy SpfAnalysisCheck must be removed before deploy';
        }

        if ($failures !== []) {
            foreach ($failures as $failure) {
                $this->error($failure);
            }

            return self::FAILURE;
        }

        $this->info('Deploy preflight passed: native SPF pipeline is mandatory and legacy fallback is absent.');

        return self::SUCCESS;
    }
}
