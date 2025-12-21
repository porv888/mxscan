<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanDelta extends Model
{
    use HasFactory;

    protected $fillable = [
        'domain_id',
        'snapshot_id',
        'changes'
    ];

    protected $casts = [
        'changes' => 'array',
    ];

    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    public function snapshot(): BelongsTo
    {
        return $this->belongsTo(ScanSnapshot::class, 'snapshot_id');
    }

    /**
     * Get changes by field type
     */
    public function getChangesByField(string $field): array
    {
        return collect($this->changes)
            ->where('field', $field)
            ->values()
            ->toArray();
    }

    /**
     * Check if a specific field changed
     */
    public function hasFieldChanged(string $field): bool
    {
        return collect($this->changes)
            ->where('field', $field)
            ->isNotEmpty();
    }

    /**
     * Get RBL listing changes
     */
    public function getRblChanges(): array
    {
        $rblChanges = collect($this->changes)
            ->where('field', 'rbl_hits')
            ->first();

        if (!$rblChanges) {
            return ['listed' => [], 'delisted' => []];
        }

        return [
            'listed' => $rblChanges['listed'] ?? [],
            'delisted' => $rblChanges['delisted'] ?? [],
        ];
    }

    /**
     * Get a human-readable summary of changes
     */
    public function getSummary(): string
    {
        $summaries = [];

        foreach ($this->changes as $change) {
            $field = $change['field'];
            
            switch ($field) {
                case 'mx_ok':
                    $summaries[] = $change['to'] ? 'MX records fixed' : 'MX records broken';
                    break;
                case 'spf_ok':
                    $summaries[] = $change['to'] ? 'SPF record fixed' : 'SPF record broken';
                    break;
                case 'dmarc_ok':
                    $summaries[] = $change['to'] ? 'DMARC record fixed' : 'DMARC record broken';
                    break;
                case 'tlsrpt_ok':
                    $summaries[] = $change['to'] ? 'TLS-RPT record added' : 'TLS-RPT record removed';
                    break;
                case 'mtasts_ok':
                    $summaries[] = $change['to'] ? 'MTA-STS record added' : 'MTA-STS record removed';
                    break;
                case 'score':
                    $summaries[] = "Score changed from {$change['from']} to {$change['to']}";
                    break;
                case 'spf_lookups':
                    $summaries[] = "SPF lookups changed from {$change['from']} to {$change['to']}";
                    break;
                case 'rbl_hits':
                    if (!empty($change['listed'])) {
                        $summaries[] = 'Listed on: ' . implode(', ', $change['listed']);
                    }
                    if (!empty($change['delisted'])) {
                        $summaries[] = 'Delisted from: ' . implode(', ', $change['delisted']);
                    }
                    break;
            }
        }

        return implode('; ', $summaries);
    }
}
