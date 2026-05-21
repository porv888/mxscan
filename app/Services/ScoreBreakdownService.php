<?php

namespace App\Services;

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
        return array_values(array_filter($breakdown, fn (array $row) => $row['earned'] < $row['possible']));
    }

    public function totalEarned(array $breakdown): int
    {
        return min(
            (int) config('dns-scoring.cap', 100),
            array_sum(array_column($breakdown, 'earned'))
        );
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
        $base = (int) config('dns-scoring.spf.base', 15);
        $bonusStrict = (int) config('dns-scoring.spf.bonus_strict', 5);
        $bonusSoft = (int) config('dns-scoring.spf.bonus_soft', 2);
        $possible = $base + $bonusStrict;
        $found = ($data['status'] ?? '') === 'found';
        $earned = 0;
        $hint = null;

        if ($found) {
            $txt = is_string($data['data'] ?? null) ? $data['data'] : '';
            $earned = $base;
            if (str_contains($txt, '-all')) {
                $earned += $bonusStrict;
            } elseif (str_contains($txt, '~all')) {
                $earned += $bonusSoft;
                $possible = $base + $bonusSoft;
            } else {
                $possible = $base;
                $hint = 'Consider adding ~all or -all to your SPF record.';
            }
        } else {
            $hint = 'Publish an SPF TXT record to prevent spoofing.';
        }

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
        $max = (int) config('dns-scoring.dkim.max', 15);
        $found = ($data['status'] ?? '') === 'found';

        return [
            'key' => 'dkim',
            'label' => config('dns-scoring.dkim.label', 'DKIM'),
            'earned' => $found ? $max : 0,
            'possible' => $max,
            'status' => $found ? 'ok' : 'missing',
            'hint' => $found ? null : 'Enable DKIM signing with your mail provider.',
        ];
    }

    private function scoreDmarc(?array $data): array
    {
        $base = (int) config('dns-scoring.dmarc.base', 20);
        $bonusReject = (int) config('dns-scoring.dmarc.bonus_reject', 5);
        $bonusQuarantine = (int) config('dns-scoring.dmarc.bonus_quarantine', 3);
        $possible = $base + $bonusReject;
        $found = ($data['status'] ?? '') === 'found';
        $earned = 0;
        $hint = null;

        if ($found) {
            $txt = is_string($data['data'] ?? null) ? $data['data'] : '';
            $earned = $base;
            if (str_contains($txt, 'p=reject')) {
                $earned += $bonusReject;
            } elseif (str_contains($txt, 'p=quarantine')) {
                $earned += $bonusQuarantine;
                $possible = $base + $bonusQuarantine;
            } else {
                $possible = $base;
                $hint = 'Strengthen DMARC policy to quarantine or reject.';
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
        $max = (int) config('dns-scoring.tlsrpt.max', 10);
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
        $dnsOnly = (int) config('dns-scoring.mtasts.dns_only', 10);
        $full = (int) config('dns-scoring.mtasts.full', 20);
        $found = ($data['status'] ?? '') === 'found';
        $hasPolicy = !empty($data['policy']);
        $earned = 0;
        $possible = $full;

        if ($found) {
            $earned = $hasPolicy ? $full : $dnsOnly;
            if (!$hasPolicy) {
                $hint = 'DNS record found; publish a valid policy file for full points.';
            } else {
                $hint = null;
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
            'hint' => $hint ?? null,
        ];
    }

    private function scoreBimi(?array $data): array
    {
        $validPts = (int) config('dns-scoring.bimi.valid', 5);
        $recordPts = (int) config('dns-scoring.bimi.record_only', 2);
        $status = $data['status'] ?? 'missing';
        $earned = match ($status) {
            'found' => $validPts,
            'partial' => $recordPts,
            default => 0,
        };
        $possible = $validPts;

        return [
            'key' => 'bimi',
            'label' => config('dns-scoring.bimi.label', 'BIMI'),
            'earned' => $earned,
            'possible' => $possible,
            'status' => $status,
            'hint' => $status === 'missing' ? 'Optional: publish a BIMI record for inbox brand logos.' : null,
        ];
    }
}
