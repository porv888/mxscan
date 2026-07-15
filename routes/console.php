<?php

use App\Jobs\SpfCheckJob;
use App\Jobs\SendWeeklyReport;
use App\Jobs\DetectDomainExpiry;
use App\Jobs\DetectSslExpiry;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Jobs\NotifyIncident;
use App\Models\Domain;
use App\Models\Incident;
use App\View\Presenters\CertificateSectionPresenter;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Facades\Mail;
use App\Mail\ExpiryReminderMail;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Schedule daily SPF checks for all active domains
Schedule::call(function () {
    $activeDomains = Domain::where('status', 'active')->get();
    
    foreach ($activeDomains as $domain) {
        SpfCheckJob::dispatch($domain->id, $domain->domain);
    }
})->daily()->name('spf-daily-check')->description('Run daily SPF checks for all active domains');

// Schedule DMARC polling
Schedule::command('mail:fetch-dmarc')
    ->everyFiveMinutes()
    ->withoutOverlapping()
    ->onOneServer()
    ->when(fn() => env('MAIL_POLL_ENABLED', false))
    ->name('dmarc-poller')
    ->description('Fetch DMARC attachments from IMAP inbox');

// Schedule SSL expiry detection (daily at 3:00 AM)
Schedule::job(new DetectSslExpiry)
    ->dailyAt('03:00')
    ->withoutOverlapping()
    ->onOneServer()
    ->when(fn() => config('expiry.enabled', true))
    ->name('detect-ssl-expiry')
    ->description('Detect SSL certificate expiry dates');

// Schedule domain expiry detection (daily at 3:15 AM)
Schedule::job(new DetectDomainExpiry)
    ->dailyAt('03:15')
    ->withoutOverlapping()
    ->onOneServer()
    ->when(fn() => config('expiry.enabled', true))
    ->name('detect-domain-expiry')
    ->description('Detect domain registration expiry dates');

// Domain expiry reminders (daily at 8:00 AM)
Schedule::call(function () {
    $now = now();
    $domains = Domain::where('status', 'active')
        ->whereNotNull('user_id')
        ->get();

    foreach ($domains as $domain) {
        if (!$domain->domain_expires_at) {
            continue;
        }

        $daysUntilExpiry = (int) $now->diffInDays($domain->domain_expires_at, false);
        if (in_array($daysUntilExpiry, [30, 7, 1], true) && $daysUntilExpiry >= 0) {
            Mail::to($domain->user->email)->send(
                new ExpiryReminderMail($domain, 'domain', $daysUntilExpiry, $domain->domain_expires_at)
            );
        }
    }
})->dailyAt('08:00')->name('domain-expiry-reminders')->description('Send domain registration expiry reminders');

// Certificate expiry reminders (daily at 8:00 AM) — deduplicated via incidents
Schedule::call(function () {
    $domains = Domain::where('status', 'active')
        ->whereNotNull('user_id')
        ->get();

    foreach ($domains as $domain) {
        $latestScan = $domain->scans()->where('status', 'finished')->latest('finished_at')->first();
        if ($latestScan === null) {
            continue;
        }

        $resultJson = $latestScan->result_json ?? [];
        if (!is_array($resultJson)) {
            continue;
        }

        $native = CertificateAnalysisReader::toNativeResult(
            $domain->domain,
            is_array($resultJson['certificates'] ?? null) ? $resultJson['certificates'] : null,
        );

        if ($native === null) {
            continue;
        }

        $alreadySent = Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'certificate_expiring')
            ->whereNull('resolved_at')
            ->get()
            ->map(fn (Incident $incident) => (string) ($incident->meta['dedup_key'] ?? ''))
            ->filter(fn (string $key) => $key !== '')
            ->values()
            ->all();

        $alerts = app(\App\Domain\EmailSecurity\Checks\Certificates\Monitoring\CertificateAlertEvaluator::class)
            ->evaluate($domain->domain, $native, $alreadySent);

        foreach ($alerts as $alert) {
            if (!is_array($alert)) {
                continue;
            }

            $dedupKey = (string) ($alert['dedup_key'] ?? '');
            if ($dedupKey === '') {
                continue;
            }

            $existing = Incident::query()
                ->where('domain_id', $domain->id)
                ->where('type', 'certificate_expiring')
                ->whereNull('resolved_at')
                ->where('meta->dedup_key', $dedupKey)
                ->exists();

            if ($existing) {
                continue;
            }

            $incident = Incident::create([
                'domain_id' => $domain->id,
                'type' => 'certificate_expiring',
                'severity' => (string) ($alert['severity'] ?? 'warning'),
                'message' => (string) ($alert['message'] ?? 'Certificate alert'),
                'meta' => [
                    'dedup_key' => $dedupKey,
                    'threshold' => $alert['threshold'] ?? null,
                    'endpoint_key' => $alert['endpoint_key'] ?? null,
                    'hostname' => $alert['hostname'] ?? null,
                    'days_remaining' => $alert['days_remaining'] ?? null,
                ],
                'occurred_at' => now(),
            ]);

            NotifyIncident::dispatch($incident);
        }
    }
})->dailyAt('08:00')->name('certificate-expiry-reminders')->description('Send deduplicated certificate expiry reminders');

// Schedule weekly reports (run every Monday at 7:00 AM)
Schedule::job(new SendWeeklyReport)
    ->weeklyOn(1, '7:00')
    ->withoutOverlapping()
    ->onOneServer()
    ->name('weekly-reports')
    ->description('Send weekly security reports to users');

// Schedule delivery monitoring collection (every 5 minutes)
Schedule::command('monitoring:collect')
    ->everyFiveMinutes()
    ->withoutOverlapping()
    ->onOneServer()
    ->name('delivery-monitoring-collect')
    ->description('Collect and process delivery monitoring test emails');

// Schedule user-configured scheduled scans (check every minute)
Schedule::command('scans:scheduled')
    ->everyMinute()
    ->withoutOverlapping()
    ->onOneServer()
    ->name('scheduled-scans')
    ->description('Run user-configured scheduled domain scans that are due');
