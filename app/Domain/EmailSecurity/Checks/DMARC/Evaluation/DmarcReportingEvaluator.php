<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evaluation;

use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParsedRecord;

final class DmarcReportingEvaluator
{
    /**
     * @return array{configured: bool, destinations: list<array<string, mixed>>, syntactic: bool}
     */
    public function evaluateAggregate(DmarcParsedRecord $parsed): array
    {
        $rua = $parsed->tag('rua');
        if ($rua === null || trim($rua) === '') {
            return ['configured' => false, 'destinations' => [], 'syntactic' => false];
        }

        $destinations = [];
        foreach ($this->parseUriList($rua) as $uri) {
            $parsedUri = $this->parseMailtoUri($uri);
            if ($parsedUri === null) {
                continue;
            }

            $email = strtolower($parsedUri['email']);
            $at = strrpos($email, '@');
            $destinationDomain = $at !== false ? substr($email, $at + 1) : '';

            $destinations[] = [
                'raw_uri' => $uri,
                'normalized_destination' => $email,
                'destination_domain' => $destinationDomain,
                'internal' => false,
                'authorization_required' => false,
                'authorization_lookup_name' => null,
                'authorization_status' => 'not_evaluated',
                'size_limit' => $parsedUri['size'],
            ];
        }

        return [
            'configured' => $destinations !== [],
            'destinations' => $destinations,
            'syntactic' => $destinations !== [],
        ];
    }

    /**
     * @return array{configured: bool, destinations: list<array<string, mixed>>, syntactic: bool}
     */
    public function evaluateFailure(DmarcParsedRecord $parsed): array
    {
        $ruf = $parsed->tag('ruf');
        if ($ruf === null || trim($ruf) === '') {
            return ['configured' => false, 'destinations' => [], 'syntactic' => false];
        }

        $destinations = [];
        foreach ($this->parseUriList($ruf) as $uri) {
            $parsedUri = $this->parseMailtoUri($uri);
            if ($parsedUri === null) {
                continue;
            }

            $email = strtolower($parsedUri['email']);
            $destinations[] = [
                'raw_uri' => $uri,
                'normalized_destination' => $email,
                'operationally_guaranteed' => false,
                'syntactically_configured' => true,
            ];
        }

        return [
            'configured' => $destinations !== [],
            'destinations' => $destinations,
            'syntactic' => $destinations !== [],
        ];
    }

    /**
     * @return list<string>
     */
    private function parseUriList(string $value): array
    {
        $uris = [];
        foreach (preg_split('/\s*,\s*/', trim($value)) ?: [] as $chunk) {
            $chunk = trim($chunk);
            if ($chunk !== '') {
                $uris[] = $chunk;
            }
        }

        return $uris;
    }

    /**
     * @return array{email: string, size: ?string}|null
     */
    private function parseMailtoUri(string $uri): ?array
    {
        $uri = trim($uri);
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

        return ['email' => $email, 'size' => $size];
    }
}
