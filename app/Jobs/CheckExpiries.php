<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Notifications\ExpiryReminder;
use App\Services\ExpiryService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class CheckExpiries implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct()
    {
        //
    }

    /**
     * Execute the job.
     */
    public function handle(ExpiryService $expiryService): void
    {
        Log::info('Starting expiry check job');

        $domains = Domain::with('user')->get();
        $notificationsSent = 0;

        foreach ($domains as $domain) {
            try {
                // Skip if user doesn't have monitoring permissions
                if (!$domain->user || !$domain->user->canUseMonitoring()) {
                    continue;
                }

                // Refresh expiry data if needed
                if ($expiryService->needsExpiryUpdate($domain)) {
                    $expiryService->refresh($domain);
                    $domain->refresh(); // Reload from database
                }

                // Check for expiry reminders
                $this->checkDomainExpiry($domain);
                $this->checkSslExpiry($domain);

            } catch (\Exception $e) {
                Log::error('Failed to check expiry for domain', [
                    'domain' => $domain->domain,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        Log::info('Expiry check job completed', [
            'domains_checked' => $domains->count(),
            'notifications_sent' => $notificationsSent,
        ]);
    }

    /**
     * Check domain registration expiry
     */
    protected function checkDomainExpiry(Domain $domain): void
    {
        if (!$domain->domain_expires_at) {
            return;
        }

        $daysUntilExpiry = $domain->getDaysUntilDomainExpiry();
        
        if ($daysUntilExpiry === null || $daysUntilExpiry < 0) {
            return;
        }

        // Send reminders at 30, 14, and 7 days
        $reminderDays = [30, 14, 7];
        
        foreach ($reminderDays as $days) {
            if ($daysUntilExpiry === $days) {
                // Check if we already sent this reminder today
                if ($this->shouldSendReminder($domain, 'domain', $days)) {
                    $domain->user->notify(new ExpiryReminder($domain, 'domain', $days));
                    
                    Log::info('Domain expiry reminder sent', [
                        'domain' => $domain->domain,
                        'days' => $days,
                        'expires_at' => $domain->domain_expires_at->toDateTimeString(),
                    ]);
                }
                break;
            }
        }
    }

    /**
     * Check SSL certificate expiry
     */
    protected function checkSslExpiry(Domain $domain): void
    {
        if (!$domain->ssl_expires_at) {
            return;
        }

        $daysUntilExpiry = $domain->getDaysUntilSslExpiry();
        
        if ($daysUntilExpiry === null || $daysUntilExpiry < 0) {
            return;
        }

        // Send reminders at 30, 14, and 7 days
        $reminderDays = [30, 14, 7];
        
        foreach ($reminderDays as $days) {
            if ($daysUntilExpiry === $days) {
                // Check if we already sent this reminder today
                if ($this->shouldSendReminder($domain, 'ssl', $days)) {
                    $domain->user->notify(new ExpiryReminder($domain, 'ssl', $days));
                    
                    Log::info('SSL expiry reminder sent', [
                        'domain' => $domain->domain,
                        'days' => $days,
                        'expires_at' => $domain->ssl_expires_at->toDateTimeString(),
                    ]);
                }
                break;
            }
        }
    }

    /**
     * Check if we should send a reminder (avoid duplicate notifications)
     */
    protected function shouldSendReminder(Domain $domain, string $type, int $days): bool
    {
        // Use cache to track sent reminders
        $cacheKey = "expiry_reminder:{$domain->id}:{$type}:{$days}:" . now()->format('Y-m-d');
        
        if (cache()->has($cacheKey)) {
            return false;
        }

        // Mark as sent for today
        cache()->put($cacheKey, true, now()->endOfDay());
        
        return true;
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('CheckExpiries job failed', [
            'error' => $exception->getMessage(),
        ]);
    }
}
