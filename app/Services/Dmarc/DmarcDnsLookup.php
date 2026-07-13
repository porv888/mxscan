<?php

namespace App\Services\Dmarc;

use App\Models\Domain;
use Carbon\Carbon;

/**
 * Fresh authoritative DMARC TXT lookup for RUA verification.
 *
 * Reconstructs each TXT RRset independently and selects the DMARC record.
 * Does not use application DNS caches or historical scan results.
 */
class DmarcDnsLookup
{
    public const RESOLVER_SOURCE = 'php_dns_get_record';

    /**
     * Reconstruct a single TXT RRset value from a dns_get_record row.
     *
     * Prefer entries[] chunks when present (joined with no separator).
     * Fall back to txt when it is a string. Never merge separate RRsets.
     */
    public function reconstructTxtFromRecord(array $record): ?string
    {
        if (isset($record['entries']) && is_array($record['entries']) && $record['entries'] !== []) {
            $chunks = [];
            foreach ($record['entries'] as $chunk) {
                if (is_string($chunk) || is_numeric($chunk)) {
                    $chunks[] = (string) $chunk;
                }
            }

            if ($chunks !== []) {
                return implode('', $chunks);
            }
        }

        if (isset($record['txt'])) {
            if (is_array($record['txt'])) {
                $chunks = [];
                foreach ($record['txt'] as $chunk) {
                    if (is_string($chunk) || is_numeric($chunk)) {
                        $chunks[] = (string) $chunk;
                    }
                }

                return $chunks !== [] ? implode('', $chunks) : null;
            }

            if (is_string($record['txt']) || is_numeric($record['txt'])) {
                return (string) $record['txt'];
            }
        }

        return null;
    }

    /**
     * Reconstruct one string per TXT RRset. Does not concatenate separate RRsets.
     *
     * @param list<array<string, mixed>> $dnsRows
     * @return list<string>
     */
    public function reconstructAllTxt(array $dnsRows): array
    {
        $reconstructed = [];

        foreach ($dnsRows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $value = $this->reconstructTxtFromRecord($row);
            if ($value !== null && $value !== '') {
                $reconstructed[] = $value;
            }
        }

        return $reconstructed;
    }

    /**
     * Select the first reconstructed TXT that begins with v=DMARC1 (case-insensitive).
     *
     * @param list<string> $reconstructed
     */
    public function selectDmarcRecord(array $reconstructed): ?string
    {
        foreach ($reconstructed as $value) {
            if (stripos(ltrim($value), 'v=DMARC1') === 0) {
                return $value;
            }
        }

        return null;
    }

    /**
     * Look up TXT records for an absolute hostname (e.g. _dmarc.example.com).
     *
     * @return array{
     *   hostname: string,
     *   raw_records: list<array<string, mixed>>,
     *   reconstructed_txt: list<string>,
     *   dmarc_record: string|null,
     *   checked_at: Carbon,
     *   resolver_source: string
     * }
     */
    public function lookup(string $hostname): array
    {
        $hostname = strtolower(trim($hostname));
        $checkedAt = now();

        $rawRecords = @dns_get_record($hostname, DNS_TXT);
        if ($rawRecords === false || !is_array($rawRecords)) {
            $rawRecords = [];
        }

        $reconstructed = $this->reconstructAllTxt($rawRecords);
        $dmarcRecord = $this->selectDmarcRecord($reconstructed);

        return [
            'hostname' => $hostname,
            'raw_records' => $rawRecords,
            'reconstructed_txt' => $reconstructed,
            'dmarc_record' => $dmarcRecord,
            'checked_at' => $checkedAt,
            'resolver_source' => self::RESOLVER_SOURCE,
        ];
    }

    /**
     * Look up the DMARC TXT for a Domain model.
     *
     * @return array{
     *   hostname: string,
     *   raw_records: list<array<string, mixed>>,
     *   reconstructed_txt: list<string>,
     *   dmarc_record: string|null,
     *   checked_at: Carbon,
     *   resolver_source: string
     * }
     */
    public function lookupForDomain(Domain $domain): array
    {
        return $this->lookup('_dmarc.' . $domain->domain);
    }
}
