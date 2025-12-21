<?php

namespace App\Notifications;

use App\Models\DeliveryMonitor;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class DeliveryIncidentAlert extends Notification implements ShouldQueue
{
    use Queueable;

    public $monitor;

    public function __construct(DeliveryMonitor $monitor)
    {
        $this->monitor = $monitor;
    }

    public function via($notifiable)
    {
        return ['mail'];
    }

    public function toMail($notifiable)
    {
        $incidentCount = $this->monitor->incidentsLast7Days();
        $latestCheck = $this->monitor->latestCheck();

        return (new MailMessage)
            ->subject('Delivery Issue Detected - ' . $this->monitor->label)
            ->greeting('Hello ' . $notifiable->name . ',')
            ->line('A delivery issue has been detected for your monitor: **' . $this->monitor->label . '**')
            ->line('**Recent Issues:** ' . $incidentCount . ' incident(s) in the last 7 days')
            ->when($latestCheck, function($mail) use ($latestCheck) {
                $issues = [];
                if ($latestCheck->spf_pass === false) $issues[] = 'SPF failed';
                if ($latestCheck->dkim_pass === false) $issues[] = 'DKIM failed';
                if ($latestCheck->dmarc_pass === false) $issues[] = 'DMARC failed';
                
                if (!empty($issues)) {
                    $mail->line('**Authentication Issues:** ' . implode(', ', $issues));
                }
                
                if ($latestCheck->tti_ms && $latestCheck->tti_ms > config('monitoring.tti_threshold_ms')) {
                    $mail->line('**Delivery Time:** ' . $latestCheck->getFormattedTti() . ' (exceeds threshold)');
                }
            })
            ->action('View Monitor Details', route('delivery-monitoring.show', $this->monitor))
            ->line('Please review your email configuration and resolve any issues.')
            ->line('Thank you for using MXScan!');
    }
}
