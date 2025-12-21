<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\Incident;
use App\Models\NotificationPref;
use App\Mail\ExpiryReminderMail;
use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class CheckExpiryReminders implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected array $thresholds = [30, 14, 7, 3, 1];

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        Log::info('CheckExpiryReminders job started');

        $today = Carbon::today('UTC');
        $incidentsCreated = 0;
        $emailsSent = 0;
        $total = 0;

        Domain::query()
            ->where('status', 'active')
            ->whereNotNull('user_id')
            ->with('user.notificationPrefs')
            ->orderBy('id')
            ->chunkById(200, function ($domains) use ($today, &$incidentsCreated, &$emailsSent, &$total) {
                foreach ($domains as $d) {
                    $total++;
                    
                    // Domain expiry
                    if ($d->domain_expires_at) {
                        $days = $today->diffInDays(Carbon::parse($d->domain_expires_at), false);
                        $result = $this->maybeAlert($d, 'domain_expiring', $days, $d->domain_expires_at);
                        
                        if ($result['incident']) $incidentsCreated++;
                        if ($result['email']) $emailsSent++;
                    }
                    
                    // SSL expiry
                    if ($d->ssl_expires_at) {
                        $days = $today->diffInDays(Carbon::parse($d->ssl_expires_at), false);
                        $result = $this->maybeAlert($d, 'ssl_expiring', $days, $d->ssl_expires_at);
                        
                        if ($result['incident']) $incidentsCreated++;
                        if ($result['email']) $emailsSent++;
                    }
                }
            });

        Log::info("CheckExpiryReminders completed: {$incidentsCreated} incidents, {$emailsSent} emails sent for {$total} domains");
    }

    /**
     * Get the matched threshold for the given days.
     */
    protected function getMatchedThreshold(int $days): ?int
    {
        foreach ($this->thresholds as $threshold) {
            if ($days <= $threshold && $days > ($this->thresholds[array_search($threshold, $this->thresholds) + 1] ?? 0)) {
                return $threshold;
            }
        }
        
        return null;
    }

    /**
     * Maybe create an alert for the given domain and expiry type.
     * Returns array with 'incident' and 'email' booleans.
     */
    protected function maybeAlert(Domain $domain, string $kind, int $days, $date): array
    {
        $result = ['incident' => false, 'email' => false];
        
        // Auto-close logic (if renewed > 30 days away):
        if ($days > 30) {
            Incident::where('domain_id', $domain->id)
                ->where('kind', $kind)
                ->whereNull('resolved_at')
                ->update(['resolved_at' => now()]);
            return $result;
        }
        
        // Check if we should alert at this threshold
        foreach ($this->thresholds as $t) {
            if ($days === $t) {
                $sev = $t < 7 ? 'critical' : 'warning';
                $type = $kind === 'domain_expiring' ? 'Domain' : 'SSL certificate';
                $message = "{$type} expires in {$t} day" . ($t !== 1 ? 's' : '') . " ({$date})";
                
                $incident = Incident::create([
                    'domain_id' => $domain->id,
                    'kind'      => $kind,
                    'severity'  => $sev,
                    'message'   => $message,
                    'context'   => [
                        'days' => $t,
                        'at' => (string)$date,
                        'threshold' => $t,
                    ],
                ]);
                
                $result['incident'] = true;
                
                // Send email if notifications enabled
                if ($this->shouldSendEmail($domain->user)) {
                    $this->sendExpiryEmail($domain, $kind === 'domain_expiring' ? 'domain' : 'ssl', $t, Carbon::parse($date));
                    $result['email'] = true;
                }
                
                break;
            }
        }
        
        return $result;
    }

    /**
     * Check if email notifications should be sent for this user.
     */
    protected function shouldSendEmail($user): bool
    {
        if (!$user) {
            return false;
        }

        $prefs = $user->notificationPrefs;
        
        if (!$prefs) {
            return true; // Default to enabled if no preferences set
        }

        return $prefs->email_enabled ?? true;
    }

    /**
     * Send expiry reminder email.
     */
    protected function sendExpiryEmail(Domain $domain, string $type, int $days, Carbon $expiryDate): void
    {
        try {
            Mail::to($domain->user->email)->send(
                new ExpiryReminderMail($domain, $type, $days, $expiryDate)
            );
            
            Log::info("Sent {$type} expiry email for {$domain->domain} to {$domain->user->email}");
        } catch (\Exception $e) {
            Log::error("Failed to send {$type} expiry email for {$domain->domain}: {$e->getMessage()}");
        }
    }
}
