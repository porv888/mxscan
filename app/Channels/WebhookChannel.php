<?php

namespace App\Channels;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class WebhookChannel
{
    /**
     * Send the given notification via webhook.
     */
    public function send(object $notifiable, Notification $notification): void
    {
        $prefs = $notifiable->getNotificationPrefs();

        if (!$prefs->webhook_enabled || empty($prefs->webhook_url)) {
            return;
        }

        $data = $notification->toWebhook($notifiable);

        if (empty($data)) {
            return;
        }

        try {
            $request = Http::timeout(10)
                ->withHeaders(['Content-Type' => 'application/json', 'User-Agent' => 'MXScan-Webhook/1.0']);

            // Add HMAC signature if secret is set
            if (!empty($prefs->webhook_secret)) {
                $payload = json_encode($data);
                $signature = hash_hmac('sha256', $payload, $prefs->webhook_secret);
                $request = $request->withHeaders(['X-MXScan-Signature' => $signature]);
            }

            $response = $request->post($prefs->webhook_url, $data);

            if (!$response->successful()) {
                Log::warning('Webhook notification failed', [
                    'url' => $prefs->webhook_url,
                    'status' => $response->status(),
                    'user_id' => $notifiable->id,
                ]);
            }
        } catch (\Exception $e) {
            Log::warning('Webhook notification error', [
                'url' => $prefs->webhook_url,
                'error' => $e->getMessage(),
                'user_id' => $notifiable->id,
            ]);
        }
    }
}
