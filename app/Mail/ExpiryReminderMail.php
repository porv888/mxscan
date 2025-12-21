<?php

namespace App\Mail;

use App\Models\Domain;
use Carbon\Carbon;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ExpiryReminderMail extends Mailable
{
    use Queueable, SerializesModels;

    public Domain $domain;
    public string $type;
    public int $days;
    public Carbon $expiryDate;

    /**
     * Create a new message instance.
     */
    public function __construct(Domain $domain, string $type, int $days, Carbon $expiryDate)
    {
        $this->domain = $domain;
        $this->type = $type;
        $this->days = $days;
        $this->expiryDate = $expiryDate;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        $typeLabel = $this->type === 'domain' ? 'Domain' : 'SSL Certificate';
        
        return new Envelope(
            subject: "[MXScan] {$this->domain->domain} {$typeLabel} expires in {$this->days} day" . ($this->days !== 1 ? 's' : ''),
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.expiry-reminder',
            with: [
                'domain' => $this->domain,
                'type' => $this->type,
                'typeLabel' => $this->type === 'domain' ? 'Domain Registration' : 'SSL Certificate',
                'days' => $this->days,
                'expiryDate' => $this->expiryDate,
                'urgency' => $this->days < 7 ? 'critical' : ($this->days < 14 ? 'high' : 'medium'),
            ],
        );
    }
}
