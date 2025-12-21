<?php

namespace App\Notifications;

use App\Models\Domain;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ExpiryReminder extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public Domain $domain,
        public string $type, // 'domain' or 'ssl'
        public int $days
    ) {
        //
    }

    /**
     * Get the notification's delivery channels.
     */
    public function via($notifiable): array
    {
        $prefs = $notifiable->getNotificationPrefs();
        
        $channels = [];
        if ($prefs->email_enabled) {
            $channels[] = 'mail';
        }

        return $channels;
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail($notifiable): MailMessage
    {
        $label = $this->type === 'ssl' ? 'SSL/TLS certificate' : 'domain registration';
        $emoji = $this->type === 'ssl' ? '🔒' : '🌐';
        $expiryDate = $this->type === 'ssl' 
            ? $this->domain->ssl_expires_at 
            : $this->domain->domain_expires_at;

        $urgencyLevel = $this->getUrgencyLevel();
        
        return (new MailMessage)
            ->subject("MXScan Reminder: {$label} expires in {$this->days} days - {$this->domain->domain}")
            ->greeting("Expiry Reminder {$emoji}")
            ->line("This is a {$urgencyLevel} reminder that your **{$label}** for **{$this->domain->domain}** is set to expire soon.")
            ->line("**Expires in:** {$this->days} days")
            ->line("**Expiry Date:** {$expiryDate->format('M j, Y')}")
            ->line($this->getActionMessage())
            ->action('View Domain Details', url("/domains/{$this->domain->id}"))
            ->line('Don\'t let your domain security lapse. Take action today!')
            ->salutation('Best regards, The MXScan Team');
    }

    /**
     * Get the array representation of the notification.
     */
    public function toArray($notifiable): array
    {
        return [
            'domain_id' => $this->domain->id,
            'domain' => $this->domain->domain,
            'type' => $this->type,
            'days' => $this->days,
            'expires_at' => $this->type === 'ssl' 
                ? $this->domain->ssl_expires_at 
                : $this->domain->domain_expires_at,
        ];
    }

    /**
     * Get urgency level based on days remaining
     */
    protected function getUrgencyLevel(): string
    {
        return match (true) {
            $this->days <= 7 => 'urgent',
            $this->days <= 14 => 'important',
            default => 'friendly'
        };
    }

    /**
     * Get action message based on type and urgency
     */
    protected function getActionMessage(): string
    {
        if ($this->type === 'ssl') {
            return match (true) {
                $this->days <= 7 => 'Please renew your SSL certificate immediately to avoid service disruption.',
                $this->days <= 14 => 'We recommend renewing your SSL certificate soon to ensure continuous security.',
                default => 'Consider renewing your SSL certificate to maintain uninterrupted secure connections.'
            };
        }

        return match (true) {
            $this->days <= 7 => 'Please renew your domain registration immediately to avoid losing control of your domain.',
            $this->days <= 14 => 'We recommend renewing your domain registration soon to avoid any service interruption.',
            default => 'Consider renewing your domain registration to ensure continuous service.'
        };
    }
}
