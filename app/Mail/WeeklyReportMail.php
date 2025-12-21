<?php

namespace App\Mail;

use App\Models\Domain;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Mail\Mailables\Attachment;
use Illuminate\Queue\SerializesModels;

class WeeklyReportMail extends Mailable implements ShouldQueue
{
    use Queueable, SerializesModels;

    public function __construct(
        public Domain $domain,
        public string $pdfContent,
        public $weekStart,
        public $weekEnd
    ) {
        //
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: "MXScan Weekly Report — {$this->domain->domain}",
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.weekly-report',
            with: [
                'domain' => $this->domain,
                'weekStart' => $this->weekStart,
                'weekEnd' => $this->weekEnd,
            ]
        );
    }

    /**
     * Get the attachments for the message.
     */
    public function attachments(): array
    {
        $filename = "mxscan-{$this->domain->domain}-weekly-" . 
                   $this->weekStart->format('Y-m-d') . ".pdf";

        return [
            Attachment::fromData(fn () => $this->pdfContent, $filename)
                ->withMime('application/pdf'),
        ];
    }
}
