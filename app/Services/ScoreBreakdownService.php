<?php

namespace App\Services;

use App\Domain\EmailSecurity\DTO\ScoreComponentDTO;

class ScoreBreakdownService
{
    /**
     * @return list<array{key: string, label: string, earned: int, possible: int, status: string, hint: ?string}>
     */
    public function buildFromDnsRecords(array $records): array
    {
        $items = [];

        $items[] = $this->scoreMx($records['MX'] ?? null);
        $items[] = $this->scoreSpf($records['SPF'] ?? null);
        $items[] = $this->scoreDkim($records['DKIM'] ?? null);
        $items[] = $this->scoreDmarc($records['DMARC'] ?? null);
        $items[] = $this->scoreTlsRpt($records['TLS-RPT'] ?? null);
        $items[] = $this->scoreMtaSts($records['MTA-STS'] ?? null);

        if (isset($records['BIMI'])) {
            $items[] = $this->scoreBimi($records['BIMI']);
        }

        return $items;
    }

    /**
     * @return list<array{key: string, label: string, earned: int, possible: int, status: string, hint: ?string}>
     */
    public function deductions(array $breakdown): array
    {
        return array_values(array_filter(
            $breakdown,
            fn (array $row) => ($row['possible'] ?? 0) > 0 && $row['earned'] < $row['possible']
        ));
    }

    public function totalEarned(array $breakdown): int
    {
        return min(
            (int) config('dns-scoring.cap', 100),
            array_sum(array_column($breakdown, 'earned'))
        );
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @return list<array<string, mixed>>
     */
    public function replaceComponent(array $breakdown, ScoreComponentDTO $component): array
    {
        $row = $component->toBreakdownRow();
        $replaced = false;

        foreach ($breakdown as $index => $existing) {
            if (($existing['key'] ?? '') === $component->key) {
                $breakdown[$index] = $row;
                $replaced = true;
                break;
            }
        }

        if (!$replaced) {
            $breakdown[] = $row;
        }

        return $breakdown;
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @return ?array<string, mixed>
     */
    public function findRow(array $breakdown, string $key): ?array
    {
        foreach ($breakdown as $row) {
            if (($row['key'] ?? '') === $key) {
                return $row;
            }
        }

        return null;
    }

    private function scoreMx(?array $data): array
    {
        $max = (int) config('dns-scoring.mx.max', 15);
        $found = ($data['status'] ?? '') === 'found';

        return [
            'key' => 'mx',
            'label' => config('dns-scoring.mx.label', 'MX Records'),
            'earned' => $found ? $max : 0,
            'possible' => $max,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $found ? null : 'Add MX records so mail can be delivered to your domain.',
        ];
    }

    private function scoreSpf(?array $data): array
    {
        $base = (int) config('dns-scoring.spf.base', 20);
        $possible = $base;
        $found = ($data['status'] ?? '') === 'found';
        $earned = $found ? $base : 0;
        $hint = $found ? null : 'Publish an SPF TXT record to prevent spoofing.';

        return [
            'key' => 'spf',
            'label' => config('dns-scoring.spf.label', 'SPF Record'),
            'earned' => $earned,
            'possible' => $possible,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $hint,
        ];
    }

    private function scoreDkim(?array $data): array
    {
        $max = (int) config('dns-scoring.dkim.max', 20);
        $found = ($data['status'] ?? '') === 'found';

        return [
            'key' => 'dkim',
            'label' => config('dns-scoring.dkim.label', 'DKIM DNS configuration'),
            'earned' => $found ? $max : 0,
            'possible' => $max,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $found
                ? 'Published DKIM DNS keys only — not proof of live signing or alignment.'
                : 'Publish DKIM DNS selectors with your mail provider.',
        ];
    }

    private function scoreDmarc(?array $data): array
    {
        $base = (int) config('dns-scoring.dmarc.base', 30);
        $possible = $base;
        $found = ($data['status'] ?? '') === 'found';
        $earned = $found ? $base : 0;
        $hint = null;

        if ($found) {
            $txt = is_string($data['data'] ?? null) ? $data['data'] : '';
            if (!str_contains($txt, 'p=reject') && !str_contains($txt, 'p=quarantine')) {
                $hint = 'DMARC is present; consider quarantine or reject for stronger protection.';
            }
        } else {
            $hint = 'Add a DMARC record at _dmarc.yourdomain.';
        }

        return [
            'key' => 'dmarc',
            'label' => config('dns-scoring.dmarc.label', 'DMARC'),
            'earned' => $earned,
            'possible' => $possible,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $hint,
        ];
    }

    private function scoreTlsRpt(?array $data): array
    {
        $max = (int) config('dns-scoring.tlsrpt.max', 5);
        $found = ($data['status'] ?? '') === 'found';

        return [
            'key' => 'tlsrpt',
            'label' => config('dns-scoring.tlsrpt.label', 'TLS-RPT'),
            'earned' => $found ? $max : 0,
            'possible' => $max,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $found ? null : 'Optional: receive TLS failure reports.',
        ];
    }

    private function scoreMtaSts(?array $data): array
    {
        $dnsOnly = (int) config('dns-scoring.mtasts.dns_only', 5);
        $full = (int) config('dns-scoring.mtasts.full', 10);
        $found = ($data['status'] ?? '') === 'found';
        $hasPolicy = !empty($data['policy']);
        $earned = 0;
        $possible = $full;
        $hint = null;

        if ($found) {
            $earned = $hasPolicy ? $full : $dnsOnly;
            if (!$hasPolicy) {
                $hint = 'DNS record found; publish a valid policy file for full points.';
            }
        } else {
            $hint = 'Add MTA-STS to enforce TLS for incoming mail.';
        }

        return [
            'key' => 'mtasts',
            'label' => config('dns-scoring.mtasts.label', 'MTA-STS'),
            'earned' => $earned,
            'possible' => $possible,
            'status' => $found ? ($hasPolicy ? 'ok' : 'partial') : 'missing',
            'hint' => $hint,
        ];
    }

    private function scoreBimi(?array $data): array
    {
        // BIMI is optional and never contributes to or deducts from the score.
        $status = $data['status'] ?? 'missing';

        return [
            'key' => 'bimi',
            'label' => config('dns-scoring.bimi.label', 'BIMI'),
            'earned' => 0,
            'possible' => 0,
            'status' => $status,
            'hint' => 'Optional branding feature — does not affect Email Security Score.',
        ];
    }
}
