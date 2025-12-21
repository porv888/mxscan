<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use App\Models\Domain;
use App\Models\Scan;

class BlacklistAlert extends Notification implements ShouldQueue
{
    use Queueable;

    protected $domain;
    protected $scan;
    protected $blacklistResults;

    /**
     * Create a new notification instance.
     */
    public function __construct(Domain $domain, Scan $scan, $blacklistResults)
    {
        $this->domain = $domain;
        $this->scan = $scan;
        $this->blacklistResults = $blacklistResults;
    }

    /**
     * Get the notification's delivery channels.
     */
    public function via($notifiable): array
    {
        return ['mail', 'database'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail($notifiable): MailMessage
    {
        $listedResults = $this->blacklistResults->where('status', 'listed');
        $listedCount = $listedResults->count();
        $uniqueIPs = $listedResults->pluck('ip_address')->unique()->count();
        
        $message = (new MailMessage)
            ->subject("🚨 Blacklist Alert: {$this->domain->domain}")
            ->greeting("Hello {$notifiable->name},")
            ->line("We've detected that your domain **{$this->domain->domain}** has been blacklisted.")
            ->line("**Alert Details:**")
            ->line("• Domain: {$this->domain->domain}")
            ->line("• Blacklisted IPs: {$uniqueIPs}")
            ->line("• Total Blacklists: {$listedCount}")
            ->line("• Scan Date: {$this->scan->created_at->format('M j, Y g:i A')}")
            ->line('')
            ->line("**Affected IP Addresses:**");

        // Add details for each blacklisted IP
        foreach ($listedResults->groupBy('ip_address') as $ip => $ipResults) {
            $providers = $ipResults->pluck('provider')->implode(', ');
            $message->line("• **{$ip}**: {$providers}");
        }

        $message->line('')
            ->line('**Immediate Actions Required:**')
            ->line('1. Review your email sending practices')
            ->line('2. Check for compromised accounts or systems')
            ->line('3. Request delisting from affected RBL providers')
            ->line('4. Monitor your domain reputation closely')
            ->action('View Detailed Results', route('scans.show', $this->scan))
            ->line('This alert was generated automatically by your EmailSec monitoring system.');

        return $message;
    }

    /**
     * Get the array representation of the notification.
     */
    public function toArray($notifiable): array
    {
        $listedCount = $this->blacklistResults->where('status', 'listed')->count();
        $uniqueIPs = $this->blacklistResults->where('status', 'listed')->pluck('ip_address')->unique()->count();
        
        return [
            'type' => 'blacklist_alert',
            'domain_id' => $this->domain->id,
            'domain_name' => $this->domain->domain,
            'scan_id' => $this->scan->id,
            'listed_count' => $listedCount,
            'unique_ips' => $uniqueIPs,
            'scan_date' => $this->scan->created_at->toISOString(),
            'message' => "Domain {$this->domain->domain} has been blacklisted on {$listedCount} RBL provider(s)"
        ];
    }
}