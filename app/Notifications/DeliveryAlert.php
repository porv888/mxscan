<?php

namespace App\Notifications;

use App\Models\Alert;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class DeliveryAlert extends Notification implements ShouldQueue
{
    use Queueable;

    protected Alert $alert;

    /**
     * Create a new notification instance.
     */
    public function __construct(Alert $alert)
    {
        $this->alert = $alert;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $domain = $this->alert->domain;
        $meta = $this->alert->meta;
        
        $message = (new MailMessage)
            ->subject("🚨 Delivery Alert: {$this->alert->getTypeLabel()} - {$domain->domain}")
            ->greeting("Hello {$notifiable->name},")
            ->line("We detected an issue with email delivery for **{$domain->domain}**:");
        
        switch ($this->alert->type) {
            case 'dmarc_fail':
                $message->line("**DMARC Authentication Failures**")
                    ->line("• {$meta['failure_count']} out of {$meta['total_checks']} checks failed DMARC authentication")
                    ->line("• Monitor: {$meta['monitor_label']}")
                    ->line("• Timeframe: Last {$meta['timeframe']}")
                    ->line('')
                    ->line('**Impact:** Emails may be rejected or marked as spam by recipients.')
                    ->line('**Action Required:** Review your DMARC, SPF, and DKIM configuration.');
                break;
                
            case 'high_tti_p95':
                $message->line("**High Time-to-Inbox (P95)**")
                    ->line("• P95 TTI: {$meta['p95_formatted']} (95th percentile)")
                    ->line("• Monitor: {$meta['monitor_label']}")
                    ->line("• Sample size: {$meta['sample_size']} checks")
                    ->line("• Timeframe: Last {$meta['timeframe']}")
                    ->line('')
                    ->line('**Impact:** Some emails are experiencing significant delays.')
                    ->line('**Action Required:** Check your mail server queue and performance.');
                break;
                
            case 'rbl_listed':
                $message->line("**Blacklist Detection**")
                    ->line("• Your mail server IP was found on one or more RBL providers")
                    ->line("• Monitor: {$meta['monitor_label']}")
                    ->line('')
                    ->line('**Impact:** Emails may be rejected by recipient servers.')
                    ->line('**Action Required:** Check blacklist status and request delisting.');
                break;
        }
        
        $message->action('View Delivery Monitoring', route('delivery-monitoring.show', $meta['monitor_id']))
            ->line('This alert was triggered based on recent delivery checks.')
            ->line('You can adjust alert settings in your account preferences.');
        
        return $message;
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'alert_id' => $this->alert->id,
            'type' => $this->alert->type,
            'domain' => $this->alert->domain->domain,
            'meta' => $this->alert->meta,
        ];
    }
}
