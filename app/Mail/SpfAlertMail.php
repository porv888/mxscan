<?php

namespace App\Mail;

use App\Models\Domain;
use App\Models\SpfCheck;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class SpfAlertMail extends Mailable implements ShouldQueue
{
    use Queueable, SerializesModels;

    /**
     * Create a new message instance.
     */
    public function __construct(
        public readonly Domain $domain,
        public readonly SpfCheck $currentCheck,
        public readonly ?SpfCheck $previousCheck,
        public readonly array $alertReasons
    ) {}

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: "[MXScan] SPF attention needed for {$this->domain->domain}",
            from: config('mail.from.address'),
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.spf-alert',
            with: [
                'domain' => $this->domain,
                'currentCheck' => $this->currentCheck,
                'previousCheck' => $this->previousCheck,
                'alertReasons' => $this->alertReasons,
                'spfUrl' => route('spf.show', $this->domain->domain),
            ]
        );
    }

    /**
     * Get the attachments for the message.
     *
     * @return array<int, \Illuminate\Mail\Mailables\Attachment>
     */
    public function attachments(): array
    {
        return [];
    }
}
