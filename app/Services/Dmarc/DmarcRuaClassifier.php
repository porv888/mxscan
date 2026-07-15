<?php

namespace App\Services\Dmarc;

use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;

/**
 * Shared DMARC RUA parser and MXScan link classifier.
 *
 * Does not use substring matching against the full record.
 * MXScan destinations are identified only when the email domain equals mxscan.me.
 */
class DmarcRuaClassifier
{
    public function __construct(
        private DmarcParser $parser,
    ) {
    }

    public const LINK_CONNECTED = 'connected';
    public const LINK_DETECTED_UNLINKED = 'detected_unlinked';
    public const LINK_NOT_CONNECTED = 'not_connected';

    public const MXSCAN_DOMAIN = 'mxscan.me';

    /**
     * @return array<string, string>
     */
    private function tagsFromParser(string $record): array
    {
        $parsed = $this->parser->parse($record);
        $tags = [];
        foreach ($parsed->tags as $key => $tag) {
            $tags[$key] = $tag['normalized'];
        }

        return $tags;
    }

    /**
     * Parse a rua= value into individual mailto recipients.
     *
     * @return list<array{email: string, raw: string, size: string|null, uri: string}>
     */
    public function parseRuaRecipients(string $ruaValue): array
    {
        $recipients = [];
        $chunks = preg_split('/\s*,\s*/', trim($ruaValue));

        foreach ($chunks as $chunk) {
            $chunk = trim($chunk);
            if ($chunk === '') {
                continue;
            }

            $parsed = $this->parseMailtoUri($chunk);
            if ($parsed !== null) {
                $recipients[] = $parsed;
            }
        }

        return $recipients;
    }

    /**
     * Parse a single mailto URI, including optional !size suffix.
     *
     * @return array{email: string, raw: string, size: string|null, uri: string}|null
     */
    public function parseMailtoUri(string $uri): ?array
    {
        $uri = trim($uri);
        if ($uri === '') {
            return null;
        }

        if (!preg_match('/^mailto:\s*(.+)$/i', $uri, $matches)) {
            return null;
        }

        $rawTarget = trim($matches[1]);
        $size = null;
        $emailPart = $rawTarget;

        if (preg_match('/^(.+?)!(.+)$/', $rawTarget, $sizeMatches)) {
            $emailPart = $sizeMatches[1];
            $size = $sizeMatches[2];
        }

        $email = strtolower(trim($emailPart));
        if ($email === '' || !str_contains($email, '@')) {
            return null;
        }

        return [
            'email' => $email,
            'raw' => $emailPart,
            'size' => $size,
            'uri' => $uri,
        ];
    }

    /**
     * True when the email domain equals mxscan.me exactly (case-insensitive).
     */
    public function isMxscanEmail(string $email): bool
    {
        $email = strtolower(trim($email));
        $at = strrpos($email, '@');
        if ($at === false) {
            return false;
        }

        return substr($email, $at + 1) === self::MXSCAN_DOMAIN;
    }

    /**
     * Classify MXScan RUA link state from persisted native analysis.
     *
     * @param array<string, mixed> $analysis
     * @return array{
     *   rua_link_state: string,
     *   has_any_mxscan_rua: bool,
     *   has_canonical_mxscan_rua: bool,
     *   recipients: list<array{email: string, raw: string, size: string|null, uri: string}>,
     *   mxscan_recipients: list<array{email: string, raw: string, size: string|null, uri: string}>,
     *   external_recipients: list<array{email: string, raw: string, size: string|null, uri: string}>
     * }
     */
    public function classifyFromAnalysis(array $analysis, string $canonicalEmail): array
    {
        $canonicalEmail = strtolower(trim($canonicalEmail));
        $reporting = is_array($analysis['aggregate_reporting'] ?? null) ? $analysis['aggregate_reporting'] : [];
        $destinations = is_array($reporting['destinations'] ?? null) ? $reporting['destinations'] : [];
        $expectation = is_array($reporting['mxscan_expectation'] ?? null) ? $reporting['mxscan_expectation'] : [];

        $recipients = [];
        $mxscan = [];
        $external = [];

        foreach ($destinations as $destination) {
            if (!is_array($destination)) {
                continue;
            }

            $email = strtolower(trim((string) ($destination['normalized_destination'] ?? '')));
            if ($email === '' || !str_contains($email, '@')) {
                continue;
            }

            $recipient = [
                'email' => $email,
                'raw' => $email,
                'size' => null,
                'uri' => (string) ($destination['raw_uri'] ?? ('mailto:' . $email)),
            ];
            $recipients[] = $recipient;

            if (($destination['internal'] ?? false) === true || $this->isMxscanEmail($email)) {
                $mxscan[] = $recipient;
            } else {
                $external[] = $recipient;
            }
        }

        $hasCanonical = ($expectation['present'] ?? false) === true
            || in_array($canonicalEmail, array_column($mxscan, 'email'), true);
        $hasAnyMxscan = count($mxscan) > 0;

        if ($hasCanonical) {
            $state = self::LINK_CONNECTED;
        } elseif ($hasAnyMxscan) {
            $state = self::LINK_DETECTED_UNLINKED;
        } else {
            $state = self::LINK_NOT_CONNECTED;
        }

        return [
            'rua_link_state' => $state,
            'has_any_mxscan_rua' => $hasAnyMxscan,
            'has_canonical_mxscan_rua' => $hasCanonical,
            'recipients' => $recipients,
            'mxscan_recipients' => $mxscan,
            'external_recipients' => $external,
        ];
    }

    /**
     * Classify MXScan RUA link state from a full DMARC record.
     *
     * @return array{
     *   rua_link_state: string,
     *   has_any_mxscan_rua: bool,
     *   has_canonical_mxscan_rua: bool,
     *   recipients: list<array{email: string, raw: string, size: string|null, uri: string}>,
     *   mxscan_recipients: list<array{email: string, raw: string, size: string|null, uri: string}>,
     *   external_recipients: list<array{email: string, raw: string, size: string|null, uri: string}>
     * }
     */
    public function classify(string $dmarcRecord, string $canonicalEmail): array
    {
        $canonicalEmail = strtolower(trim($canonicalEmail));
        $parts = $this->tagsFromParser($dmarcRecord);
        $ruaValue = $parts['rua'] ?? '';
        $recipients = $ruaValue !== '' ? $this->parseRuaRecipients($ruaValue) : [];

        $mxscan = [];
        $external = [];
        $hasCanonical = false;

        foreach ($recipients as $recipient) {
            if ($this->isMxscanEmail($recipient['email'])) {
                $mxscan[] = $recipient;
                if ($recipient['email'] === $canonicalEmail) {
                    $hasCanonical = true;
                }
            } else {
                $external[] = $recipient;
            }
        }

        $hasAnyMxscan = count($mxscan) > 0;

        if ($hasCanonical) {
            $state = self::LINK_CONNECTED;
        } elseif ($hasAnyMxscan) {
            $state = self::LINK_DETECTED_UNLINKED;
        } else {
            $state = self::LINK_NOT_CONNECTED;
        }

        return [
            'rua_link_state' => $state,
            'has_any_mxscan_rua' => $hasAnyMxscan,
            'has_canonical_mxscan_rua' => $hasCanonical,
            'recipients' => $recipients,
            'mxscan_recipients' => $mxscan,
            'external_recipients' => $external,
        ];
    }

    /**
     * Rewrite a DMARC record so RUA has exactly one canonical MXScan address
     * and all other @mxscan.me recipients are removed. External recipients are preserved.
     *
     * @return array{
     *   current: string,
     *   updated: string,
     *   mxscan_already_present: bool,
     *   action: string,
     *   existing_rua: string|null,
     *   rua_link_state: string
     * }
     */
    public function rewriteRua(string $dmarcRecord, string $canonicalEmail): array
    {
        $canonicalEmail = strtolower(trim($canonicalEmail));
        $parts = $this->tagsFromParser($dmarcRecord);
        $existingRua = $parts['rua'] ?? '';
        $classification = $this->classify($dmarcRecord, $canonicalEmail);

        $hasCanonical = $classification['has_canonical_mxscan_rua'];
        $mxscanCount = count($classification['mxscan_recipients']);
        $external = $classification['external_recipients'];

        // Already correct: exactly one canonical MXScan recipient, no extras.
        if ($hasCanonical && $mxscanCount === 1) {
            return [
                'current' => $dmarcRecord,
                'updated' => $dmarcRecord,
                'mxscan_already_present' => true,
                'action' => 'none',
                'existing_rua' => $existingRua !== '' ? $existingRua : null,
                'rua_link_state' => self::LINK_CONNECTED,
            ];
        }

        $newRecipients = [];
        foreach ($external as $recipient) {
            $newRecipients[] = $this->formatMailto($recipient['email'], $recipient['size']);
        }
        $newRecipients[] = 'mailto:' . $canonicalEmail;

        $newRua = implode(',', $newRecipients);
        $parts['rua'] = $newRua;
        $updatedRecord = $this->buildDmarcRecord($parts);

        if ($existingRua === '') {
            $action = 'add_rua';
        } elseif ($classification['has_any_mxscan_rua']) {
            $action = 'relink_rua';
        } else {
            $action = 'append_rua';
        }

        return [
            'current' => $dmarcRecord,
            'updated' => $updatedRecord,
            'mxscan_already_present' => $hasCanonical,
            'action' => $action,
            'existing_rua' => $existingRua !== '' ? $existingRua : null,
            'rua_link_state' => $classification['rua_link_state'],
        ];
    }

    /**
     * Build a DMARC record string from parsed parts.
     *
     * @param array<string, string> $parts
     */
    public function buildDmarcRecord(array $parts): string
    {
        $record = 'v=DMARC1';
        unset($parts['v']);

        $order = ['p', 'sp', 'rua', 'ruf', 'pct', 'adkim', 'aspf', 'fo', 'rf', 'ri'];

        foreach ($order as $key) {
            if (isset($parts[$key])) {
                $record .= '; ' . $key . '=' . $parts[$key];
                unset($parts[$key]);
            }
        }

        foreach ($parts as $key => $value) {
            $record .= '; ' . $key . '=' . $value;
        }

        return $record;
    }

    protected function formatMailto(string $email, ?string $size): string
    {
        $uri = 'mailto:' . $email;
        if ($size !== null && $size !== '') {
            $uri .= '!' . $size;
        }

        return $uri;
    }
}
