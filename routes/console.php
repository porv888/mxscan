<?php

use App\Jobs\SpfCheckJob;
use App\Jobs\SendWeeklyReport;
use App\Jobs\DetectDomainExpiry;
use App\Jobs\DetectSslExpiry;
use App\Models\Domain;
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

// Simple expiry reminder check (daily at 8:00 AM)
Schedule::call(function () {
    $now = now();
    $domains = Domain::where('status', 'active')
        ->whereNotNull('user_id')
        ->get();
    
    foreach ($domains as $domain) {
        // Check domain expiry
        if ($domain->domain_expires_at) {
            $daysUntilExpiry = (int) $now->diffInDays($domain->domain_expires_at, false);
            
            // Send reminders at 30, 7, and 1 day before expiry
            if (in_array($daysUntilExpiry, [30, 7, 1]) && $daysUntilExpiry >= 0) {
                Mail::to($domain->user->email)->send(
                    new ExpiryReminderMail($domain, 'domain', $daysUntilExpiry, $domain->domain_expires_at)
                );
            }
        }
        
        // Check SSL expiry
        if ($domain->ssl_expires_at) {
            $daysUntilExpiry = (int) $now->diffInDays($domain->ssl_expires_at, false);
            
            // Send reminders at 30, 7, and 1 day before expiry
            if (in_array($daysUntilExpiry, [30, 7, 1]) && $daysUntilExpiry >= 0) {
                Mail::to($domain->user->email)->send(
                    new ExpiryReminderMail($domain, 'ssl', $daysUntilExpiry, $domain->ssl_expires_at)
                );
            }
        }
    }
})->dailyAt('08:00')->name('expiry-reminders')->description('Send domain and SSL expiry reminders');

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
