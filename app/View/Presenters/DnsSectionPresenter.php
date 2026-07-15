<?php

namespace App\View\Presenters;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Models\Domain;
use App\Models\Scan;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\ScanReport\ScanReportStatusMapper;
use Illuminate\Support\Str;

/**
 * View-only presenter for the scan report DNS section.
 * Maps existing scan payloads into summary tiles and detail panels.
 */
class DnsSectionPresenter
{
    /** @var array<string, array{title: string, text: string, impact: string, fix: string}> */
    protected array $recordHelp = [
        'mx' => [
            'title' => 'MX records',
            'text' => 'MX records tell other mail servers where to deliver email for your domain.',
            'impact' => 'Without MX records, people may not be able to send email to this domain.',
            'fix' => 'Add the mail server records from your email provider.',
        ],
        'spf' => [
            'title' => 'SPF record',
            'text' => 'SPF tells inboxes which servers are allowed to send email for your domain.',
            'impact' => 'Without SPF, attackers can spoof your domain more easily and your real emails may go to spam.',
            'fix' => 'Add one SPF TXT record that includes your sending services.',
        ],
        'spf_lookup' => [
            'title' => 'SPF lookup limit',
            'text' => 'SPF has a 10 lookup limit.',
            'impact' => 'If you go over it, some receivers may treat SPF as failed.',
            'fix' => 'Remove unused senders or use the SPF optimizer.',
        ],
        'dkim' => [
            'title' => 'DKIM',
            'text' => 'DKIM adds a digital signature that proves your email was not changed in transit.',
            'impact' => 'Without DKIM, inboxes have less trust in your email and DMARC protection is weaker.',
            'fix' => 'Enable DKIM signing in your email provider.',
        ],
        'dmarc' => [
            'title' => 'DMARC policy',
            'text' => 'DMARC tells inboxes what to do when SPF or DKIM checks fail.',
            'impact' => 'Without DMARC, spoofed emails using your domain are harder to stop and track.',
            'fix' => 'Add a DMARC TXT record at _dmarc.',
        ],
        'dmarc_reports' => [
            'title' => 'DMARC reports',
            'text' => 'DMARC reports show who is sending email as your domain.',
            'impact' => 'Without reports, you cannot see abuse, failed senders, or sending volume.',
            'fix' => 'Add the MXScan RUA address to your DMARC record.',
        ],
        'tlsrpt' => [
            'title' => 'TLS-RPT',
            'text' => 'TLS-RPT sends reports when secure mail delivery has problems.',
            'impact' => 'Without it, TLS delivery failures may happen without you knowing.',
            'fix' => 'Add a TLS-RPT TXT record.',
        ],
        'mtasts' => [
            'title' => 'MTA-STS',
            'text' => 'MTA-STS tells other mail servers to use secure encrypted delivery to your domain.',
            'impact' => 'Without it, some mail connections may be easier to downgrade or intercept.',
            'fix' => 'Add the DNS record and publish an MTA-STS policy file.',
        ],
        'bimi' => [
            'title' => 'BIMI',
            'text' => 'BIMI publishes brand indicator configuration for participating mailbox providers.',
            'impact' => 'Optional readiness check — does not affect Email Security Score. Logo display remains subject to mailbox-provider policy.',
            'fix' => 'Publish a BIMI record with a valid SVG Tiny P/S logo.',
        ],
    ];

    /**
     * @param array<string, mixed> $records
     * @param array<string, mixed> $statusCards
     * @param array<string, mixed>|null $dmarcStatus
     * @param array<string, mixed>|null $mxInfo
     */
    public function __construct(
        protected array $records,
        protected array $statusCards,
        protected ?array $dmarcStatus,
        protected ?int $spfLookupCount,
        protected Domain $domain,
        protected ?string $dmarcPolicy = null,
        protected ?bool $dmarcAligned = null,
        protected ?string $dmarcAlignmentVerification = null,
        protected ?array $dkimInfo = null,
        protected int $spfMax = 10,
        protected ?array $mxInfo = null,
        protected ?array $bimiInfo = null,
        protected ?Scan $scan = null,
    ) {
    }

    public function sectionOpenByDefault(): bool
    {
        return !$this->allGreen();
    }

    public function allGreen(): bool
    {
        foreach (['MX', 'SPF', 'DKIM', 'DMARC', 'TLS-RPT', 'MTA-STS'] as $key) {
            if ($key === 'MX') {
                if (!in_array($this->statusCards['mx']['state'] ?? '', [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)) {
                    return false;
                }
                continue;
            }

            if (($this->records[$key]['status'] ?? null) !== 'found') {
                return false;
            }
        }

        return true;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function summaryTiles(): array
    {
        $tiles = [
            $this->spfSummaryTile(),
            $this->dkimSummaryTile(),
            $this->dmarcSummaryTile(),
        ];

        if ($this->dmarcStatus !== null) {
            $tiles[] = $this->dmarcReportsSummaryTile();
        }

        $tiles[] = $this->mxSummaryTile();
        $tiles[] = $this->tlsRptSummaryTile();
        $tiles[] = $this->mtaStsSummaryTile();

        if ($this->bimiPresent()) {
            $tiles[] = $this->bimiSummaryTile();
        }

        return $tiles;
    }

    /**
     * @return list<array{label: string, items: list<array<string, mixed>>}>
     */
    public function detailGroups(): array
    {
        $firstOpenId = $this->firstOpenDetailId();

        $groups = [
            [
                'label' => 'Authentication',
                'items' => [
                    $this->spfDetail($firstOpenId),
                    $this->dkimDetail($firstOpenId),
                    $this->dmarcDetail($firstOpenId),
                ],
            ],
        ];

        if ($this->dmarcStatus !== null) {
            $groups[0]['items'][] = $this->dmarcReportsDetail($firstOpenId);
        }

        $groups[] = [
            'label' => 'Mail routing & reporting',
            'items' => [
                $this->mxDetail($firstOpenId),
                $this->tlsRptDetail($firstOpenId),
            ],
        ];

        $groups[] = [
            'label' => 'Transport security',
            'items' => [
                $this->mtaStsDetail($firstOpenId),
            ],
        ];

        if ($this->bimiPresent()) {
            $groups[] = [
                'label' => 'Optional branding',
                'items' => [
                    $this->bimiDetail($firstOpenId),
                ],
            ];
        }

        return $groups;
    }

    /**
     * @return array<string, array{title: string, text: string, impact: string, fix: string}>
     */
    public function recordHelp(): array
    {
        return $this->recordHelp;
    }

    public function dmarcShowUrl(): string
    {
        return route('dmarc.show', $this->domain);
    }

    public function spfOptimizeUrl(): string
    {
        return route('spf.show', $this->domain);
    }

    public function domainName(): string
    {
        return $this->domain->domain ?? (string) $this->domain;
    }

    protected function firstOpenDetailId(): ?string
    {
        foreach ($this->detailOrder() as $key) {
            if ($this->detailNeedsAttention($key)) {
                return 'dns-' . str_replace('_', '-', $key) . '-detail';
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    protected function detailOrder(): array
    {
        $order = ['spf', 'dkim', 'dmarc'];

        if ($this->dmarcStatus !== null) {
            $order[] = 'dmarc_reports';
        }

        return array_merge($order, ['mx', 'tlsrpt', 'mtasts', 'bimi']);
    }

    protected function detailNeedsAttention(string $key): bool
    {
        return match ($key) {
            'spf' => ($this->records['SPF']['status'] ?? '') !== 'found'
                || in_array($this->statusCards['spf']['state'] ?? '', [ScanReportStatusMapper::FAIL, ScanReportStatusMapper::WARNING], true),
            'dkim' => ($this->records['DKIM']['status'] ?? '') !== 'found',
            'dmarc' => ($this->records['DMARC']['status'] ?? '') !== 'found'
                || ($this->statusCards['dmarc']['state'] ?? '') === ScanReportStatusMapper::WARNING,
            'dmarc_reports' => $this->dmarcReportsNeedsAttention(),
            'mx' => !in_array($this->statusCards['mx']['state'] ?? '', [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true),
            'tlsrpt' => ($this->records['TLS-RPT']['status'] ?? '') !== 'found',
            'mtasts' => !in_array($this->statusCards['mtasts']['state'] ?? '', [ScanReportStatusMapper::PASS], true),
            'bimi' => ($this->records['BIMI']['status'] ?? '') === 'partial',
            default => false,
        };
    }

    protected function dmarcReportsNeedsAttention(): bool
    {
        if ($this->dmarcStatus === null) {
            return false;
        }

        $state = $this->dmarcStatus['rua_link_state'] ?? '';
        $status = $this->dmarcStatus['status'] ?? '';

        if (in_array($state, [DmarcStatusService::RUA_LINK_DETECTED_UNLINKED, DmarcStatusService::RUA_LINK_NOT_CONNECTED], true)) {
            return true;
        }

        return in_array($status, [
            DmarcStatusService::STATUS_NOT_ENABLED,
            DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN,
            DmarcStatusService::STATUS_STALE,
        ], true);
    }

    protected function bimiPresent(): bool
    {
        return array_key_exists('BIMI', $this->records) && $this->records['BIMI'] !== null;
    }

    /**
     * @return array{variant: string, severity: string}
     */
    protected function mapState(?string $state, bool $found = true): array
    {
        if (!$found) {
            return ['variant' => 'danger', 'severity' => 'danger'];
        }

        return match ($state) {
            ScanReportStatusMapper::PASS => ['variant' => 'success', 'severity' => 'success'],
            ScanReportStatusMapper::WARNING => ['variant' => 'warning', 'severity' => 'warning'],
            ScanReportStatusMapper::FAIL, ScanReportStatusMapper::MISSING => ['variant' => 'danger', 'severity' => 'danger'],
            ScanReportStatusMapper::NOT_CHECKED => ['variant' => 'info', 'severity' => 'neutral'],
            ScanReportStatusMapper::NOT_APPLICABLE => ['variant' => 'neutral', 'severity' => 'neutral'],
            default => ['variant' => 'neutral', 'severity' => 'neutral'],
        };
    }

    protected function severityAccent(string $severity): string
    {
        return match ($severity) {
            'danger' => 'border-l-4 border-red-500',
            'warning' => 'border-l-4 border-amber-500',
            'success' => 'border-l-4 border-green-500/60',
            default => 'border-l-4 border-gray-200 dark:border-gray-600',
        };
    }

    protected function spfSummaryTile(): array
    {
        $card = $this->statusCards['spf'] ?? [];
        $found = ($this->records['SPF']['status'] ?? '') === 'found';
        $style = $this->mapState($card['state'] ?? null, $found);
        $detailId = 'dns-spf-detail';

        if (!$found) {
            return [
                'id' => 'dns-spf',
                'label' => 'SPF',
                'badgeVariant' => 'danger',
                'badgeLabel' => 'Missing',
                'severity' => 'danger',
                'accent' => $this->severityAccent('danger'),
                'summary' => 'No SPF record found. Mail receivers cannot validate allowed senders.',
                'primaryAction' => ['label' => 'Add SPF', 'href' => '#fix-pack'],
                'detailId' => $detailId,
            ];
        }

        $summary = match ($card['state'] ?? '') {
            ScanReportStatusMapper::FAIL => $card['subtext'] ?? 'SPF record failed validation.',
            ScanReportStatusMapper::WARNING => $card['subtext'] ?? 'SPF lookup count is near the limit.',
            ScanReportStatusMapper::NOT_CHECKED => 'SPF record found. Lookup calculation did not run.',
            default => ($card['subtext'] ?? 'SPF record found.') . ' Mail receivers can validate allowed senders.',
        };

        return [
            'id' => 'dns-spf',
            'label' => 'SPF',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Configured',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => $summary,
            'primaryAction' => null,
            'detailId' => $detailId,
        ];
    }

    protected function dkimSummaryTile(): array
    {
        $card = $this->statusCards['dkim'] ?? [];
        $found = in_array($card['state'] ?? '', [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)
            && (($card['count'] ?? 0) >= 1);
        $style = $this->mapState($card['state'] ?? null, $found);
        $detailId = 'dns-dkim-detail';

        if (!$found) {
            return [
                'id' => 'dns-dkim',
                'label' => 'DKIM DNS',
                'badgeVariant' => $style['variant'],
                'badgeLabel' => $card['state'] === ScanReportStatusMapper::UNKNOWN ? 'Unknown' : 'Missing',
                'severity' => $style['severity'],
                'accent' => $this->severityAccent($style['severity']),
                'summary' => $card['status'] ?? 'No DKIM key was found for the tested selectors.',
                'primaryAction' => ['label' => 'Add DKIM', 'href' => '#fix-pack'],
                'detailId' => $detailId,
            ];
        }

        return [
            'id' => 'dns-dkim',
            'label' => 'DKIM DNS',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['state'] === ScanReportStatusMapper::WARNING ? 'Warning' : 'Configured',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => ($card['status'] ?? 'A valid DKIM key is published for a tested selector.') . ' This confirms DNS keys only.',
            'primaryAction' => null,
            'detailId' => $detailId,
        ];
    }

    protected function dmarcSummaryTile(): array
    {
        $card = $this->statusCards['dmarc'] ?? [];
        $found = ($this->records['DMARC']['status'] ?? '') === 'found';
        $style = $this->mapState($card['state'] ?? null, $found);
        $detailId = 'dns-dmarc-detail';

        if (!$found) {
            return [
                'id' => 'dns-dmarc',
                'label' => 'DMARC',
                'badgeVariant' => 'danger',
                'badgeLabel' => 'Missing',
                'severity' => 'danger',
                'accent' => $this->severityAccent('danger'),
                'summary' => 'No DMARC policy found. Spoofed emails are harder to stop and track.',
                'primaryAction' => ['label' => 'Add DMARC', 'href' => '#fix-pack'],
                'detailId' => $detailId,
            ];
        }

        $policy = $card['policy'] ?? $this->dmarcPolicy;
        $summary = $policy
            ? 'Policy: ' . $policy . '.'
            : 'DMARC policy record found.';

        return [
            'id' => 'dns-dmarc',
            'label' => 'DMARC',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Configured',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => $summary,
            'primaryAction' => null,
            'detailId' => $detailId,
        ];
    }

    protected function dmarcReportsSummaryTile(): array
    {
        $status = $this->dmarcStatus;
        $detailId = 'dns-dmarc-reports-detail';
        $dmarcUrl = $this->dmarcShowUrl();
        $ruaState = $status['rua_link_state'] ?? '';
        $lifecycle = $status['status'] ?? '';

        if ($ruaState === DmarcStatusService::RUA_LINK_DETECTED_UNLINKED) {
            return [
                'id' => 'dns-dmarc-reports',
                'label' => 'DMARC Reports',
                'badgeVariant' => 'warning',
                'badgeLabel' => 'Relink required',
                'severity' => 'warning',
                'accent' => $this->severityAccent('warning'),
                'summary' => 'MXScan reporting is present, but not linked to this domain.',
                'primaryAction' => ['label' => 'Fix reporting', 'href' => $dmarcUrl],
                'detailId' => $detailId,
            ];
        }

        if ($ruaState === DmarcStatusService::RUA_LINK_NOT_CONNECTED && ($status['has_rua'] ?? false)) {
            return [
                'id' => 'dns-dmarc-reports',
                'label' => 'DMARC Reports',
                'badgeVariant' => 'warning',
                'badgeLabel' => 'Action required',
                'severity' => 'warning',
                'accent' => $this->severityAccent('warning'),
                'summary' => 'Connect MXScan reporting to identify senders and authentication failures.',
                'primaryAction' => ['label' => 'Connect reporting', 'href' => $dmarcUrl],
                'detailId' => $detailId,
            ];
        }

        if ($lifecycle === DmarcStatusService::STATUS_ACTIVE) {
            $summary = ($status['has_reports'] ?? false) && $this->domain->dmarc_last_report_at
                ? 'Reports are being collected. Last report ' . $this->domain->dmarc_last_report_at->diffForHumans() . '.'
                : 'MXScan reporting is connected.';

            return [
                'id' => 'dns-dmarc-reports',
                'label' => 'DMARC Reports',
                'badgeVariant' => 'success',
                'badgeLabel' => 'Active',
                'severity' => 'success',
                'accent' => $this->severityAccent('success'),
                'summary' => $summary,
                'primaryAction' => ['label' => 'Open DMARC visibility', 'href' => $dmarcUrl],
                'detailId' => $detailId,
            ];
        }

        if ($lifecycle === DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING) {
            return [
                'id' => 'dns-dmarc-reports',
                'label' => 'DMARC Reports',
                'badgeVariant' => 'info',
                'badgeLabel' => 'Waiting',
                'severity' => 'neutral',
                'accent' => $this->severityAccent('neutral'),
                'summary' => 'Waiting for first report. Reports usually arrive within 24–48 hours.',
                'primaryAction' => ['label' => 'Open DMARC visibility', 'href' => $dmarcUrl],
                'detailId' => $detailId,
            ];
        }

        return [
            'id' => 'dns-dmarc-reports',
            'label' => 'DMARC Reports',
            'badgeVariant' => 'neutral',
            'badgeLabel' => $status['label'] ?? 'Not enabled',
            'severity' => 'neutral',
            'accent' => $this->severityAccent('neutral'),
            'summary' => 'Add MXScan RUA to receive aggregate reports.',
            'primaryAction' => ['label' => 'Set up reporting', 'href' => $dmarcUrl],
            'detailId' => $detailId,
        ];
    }

    protected function mxSummaryTile(): array
    {
        $card = $this->statusCards['mx'] ?? [];
        $analysis = MxAnalysisReader::analysis($this->mxInfo)
            ?? MxAnalysisReader::fromLegacyDnsRecord($this->records['MX'] ?? null, $this->mxInfo);
        $style = $this->mapState($card['state'] ?? null, ($this->records['MX']['status'] ?? '') === 'found');
        $detailId = 'dns-mx-detail';

        return [
            'id' => 'dns-mx',
            'label' => 'MX',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Unknown',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => $analysis['summary'] ?? ($card['status'] ?? 'MX configuration could not be evaluated.'),
            'primaryAction' => null,
            'detailId' => $detailId,
        ];
    }

    protected function tlsRptSummaryTile(): array
    {
        $card = $this->statusCards['tlsrpt'] ?? [];
        $record = $this->records['TLS-RPT'] ?? null;
        $style = $this->mapState($card['state'] ?? null, ($record['status'] ?? '') === 'found');

        return [
            'id' => 'dns-tlsrpt',
            'label' => 'TLS-RPT',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Not set up',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => ($record['status'] ?? '') === 'found'
                ? ($card['status'] ?? 'TLS reporting is configured.')
                : 'No TLS-RPT record found. Mail delivery security problems may go unnoticed.',
            'primaryAction' => ($card['state'] ?? '') === ScanReportStatusMapper::PASS
                ? null
                : ['label' => 'Add policy', 'href' => '#fix-pack'],
            'detailId' => 'dns-tlsrpt-detail',
        ];
    }

    protected function mtaStsSummaryTile(): array
    {
        $card = $this->statusCards['mtasts'] ?? [];
        $record = $this->records['MTA-STS'] ?? null;
        $style = $this->mapState($card['state'] ?? null, ($record['status'] ?? '') === 'found');

        return [
            'id' => 'dns-mtasts',
            'label' => 'MTA-STS',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Not set up',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => ($record['status'] ?? '') === 'found'
                ? ($card['status'] ?? 'MTA-STS configured.')
                : 'No MTA-STS policy found. Secure mail delivery is less protected.',
            'primaryAction' => ($card['state'] ?? '') === ScanReportStatusMapper::PASS
                ? null
                : ['label' => 'Add policy', 'href' => '#fix-pack'],
            'detailId' => 'dns-mtasts-detail',
        ];
    }

    /**
     * @param array<string, mixed>|null $record
     * @param array<string, mixed> $card
     * @return array<string, mixed>
     */
    protected function simplePresenceTile(
        string $label,
        string $id,
        string $detailId,
        string $cardKey,
        ?array $record,
        array $card,
        string $missingSummary,
        string $missingActionLabel,
    ): array {
        $found = ($record['status'] ?? '') === 'found';

        if (!$found) {
            return [
                'id' => $id,
                'label' => $label,
                'badgeVariant' => 'danger',
                'badgeLabel' => 'Missing',
                'severity' => 'danger',
                'accent' => $this->severityAccent('danger'),
                'summary' => $missingSummary,
                'primaryAction' => ['label' => $missingActionLabel, 'href' => '#fix-pack'],
                'detailId' => $detailId,
            ];
        }

        return [
            'id' => $id,
            'label' => $label,
            'badgeVariant' => 'success',
            'badgeLabel' => 'Configured',
            'severity' => 'success',
            'accent' => $this->severityAccent('success'),
            'summary' => $label . ' record found.',
            'primaryAction' => null,
            'detailId' => $detailId,
        ];
    }

    protected function bimiSummaryTile(): array
    {
        $card = $this->statusCards['bimi'] ?? [];
        $record = $this->records['BIMI'] ?? null;
        $style = $this->mapState($card['state'] ?? null, ($record['status'] ?? '') === 'found');

        return [
            'id' => 'dns-bimi',
            'label' => 'BIMI',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Optional',
            'severity' => $style['severity'],
            'accent' => $this->severityAccent($style['severity']),
            'summary' => $card['subtext'] ?? 'Optional branding feature.',
            'primaryAction' => null,
            'detailId' => 'dns-bimi-detail',
        ];
    }

    protected function spfDetail(?string $firstOpenId): array
    {
        $data = $this->records['SPF'] ?? null;
        $found = ($data['status'] ?? '') === 'found';
        $card = $this->statusCards['spf'] ?? [];
        $style = $this->mapState($card['state'] ?? null, $found);
        $id = 'dns-spf-detail';

        $explanation = $found
            ? 'SPF tells inboxes which servers are allowed to send email for your domain.'
            : 'Without SPF, attackers can spoof your domain more easily and your real emails may go to spam.';

        $detail = [
            'id' => $id,
            'key' => 'spf',
            'label' => 'SPF',
            'helpKey' => 'spf',
            'badgeVariant' => $found ? $style['variant'] : 'danger',
            'badgeLabel' => $found ? ($card['status'] ?? 'Configured') : 'Missing',
            'severity' => $found ? $style['severity'] : 'danger',
            'explanation' => $explanation,
            'open' => $id === $firstOpenId,
            'primaryAction' => $found ? null : ['label' => 'Add SPF', 'href' => '#fix-pack'],
            'type' => 'code',
            'value' => $found ? (string) ($data['data'] ?? '') : null,
            'copyLabel' => 'Copy SPF record',
            'footer' => null,
        ];

        if ($found && $this->spfLookupCount !== null) {
            $detail['lookupCount'] = $this->spfLookupCount;
            $detail['lookupMax'] = $this->spfMax;
            $detail['showOptimize'] = $this->spfLookupCount >= 7;
        }

        return $detail;
    }

    protected function dkimDetail(?string $firstOpenId): array
    {
        $data = $this->records['DKIM'] ?? null;
        $card = $this->statusCards['dkim'] ?? [];
        $found = in_array($card['state'] ?? '', [ScanReportStatusMapper::PASS, ScanReportStatusMapper::WARNING], true)
            && (($card['count'] ?? 0) >= 1);
        $id = 'dns-dkim-detail';
        $selectors = [];

        if ($found) {
            $analysis = DkimAnalysisReader::analysis($this->dkimInfo);
            $analysisSelectors = is_array($analysis['selectors'] ?? null) ? $analysis['selectors'] : [];
            $validAnalysisSelectors = array_values(array_filter(
                $analysisSelectors,
                fn (array $row) => ($row['record_status'] ?? '') === 'valid',
            ));

            if ($validAnalysisSelectors !== []) {
                foreach ($validAnalysisSelectors as $row) {
                    $selectorName = $row['selector'] ?? 'unknown';
                    $selectors[] = [
                        'selector' => $selectorName,
                        'host' => ($row['hostname'] ?? ($selectorName . '._domainkey.' . $this->domainName())),
                        'record' => '',
                        'preview' => 'Valid DKIM key published',
                        'key_type' => $row['key_type'] ?? null,
                        'key_bits' => $row['key_bits'] ?? null,
                    ];
                }
            } elseif (is_array($data['data'] ?? null)) {
                foreach ($data['data'] as $row) {
                    $selectors[] = [
                        'selector' => $row['selector'] ?? 'unknown',
                        'host' => ($row['selector'] ?? 'unknown') . '._domainkey.' . $this->domainName(),
                        'record' => $row['record'] ?? '',
                        'preview' => Str::limit((string) ($row['record'] ?? ''), 80),
                        'key_type' => $row['key_type'] ?? null,
                        'key_bits' => $row['key_bits'] ?? null,
                    ];
                }
            }
        }

        return [
            'id' => $id,
            'key' => 'dkim',
            'label' => 'DKIM DNS',
            'helpKey' => 'dkim',
            'badgeVariant' => $found ? 'success' : 'warning',
            'badgeLabel' => $found ? 'Configured' : ($card['state'] === ScanReportStatusMapper::UNKNOWN ? 'Unknown' : 'Missing'),
            'severity' => $found ? 'success' : 'warning',
            'explanation' => $found
                ? ($card['status'] ?? count($selectors) . ' valid key(s) found') . '.'
                : ($card['status'] ?? 'No DKIM key was found for the tested selectors.'),
            'open' => $id === $firstOpenId,
            'primaryAction' => $found ? null : ['label' => 'Add DKIM', 'href' => '#fix-pack'],
            'type' => 'dkim',
            'dnsOnlyNote' => $card['explanation'] ?? 'This confirms published DNS keys only. Live signing and alignment require DMARC report or email-header evidence.',
            'selectors' => $selectors,
            'checkedCount' => count(config('dkim.selectors', [])),
        ];
    }

    protected function dmarcDetail(?string $firstOpenId): array
    {
        $data = $this->records['DMARC'] ?? null;
        $card = $this->statusCards['dmarc'] ?? [];
        $found = ($data['status'] ?? '') === 'found';
        $style = $this->mapState($card['state'] ?? null, $found);
        $id = 'dns-dmarc-detail';
        $policy = $card['policy'] ?? $this->dmarcPolicy;

        return [
            'id' => $id,
            'key' => 'dmarc',
            'label' => 'DMARC Policy',
            'helpKey' => 'dmarc',
            'badgeVariant' => $found ? $style['variant'] : 'danger',
            'badgeLabel' => $found ? ($card['status'] ?? 'Configured') : 'Missing',
            'severity' => $found ? $style['severity'] : 'danger',
            'explanation' => $found
                ? ($policy ? 'Policy: ' . $policy . '.' : 'DMARC policy record found.')
                : 'Without DMARC, spoofed emails using your domain are harder to stop and track.',
            'open' => $id === $firstOpenId,
            'primaryAction' => $found ? null : ['label' => 'Add DMARC', 'href' => '#fix-pack'],
            'type' => 'code',
            'value' => $found ? (string) ($data['data'] ?? '') : null,
            'copyLabel' => 'Copy DMARC record',
            'chips' => array_filter([
                $policy ? 'Policy: ' . $policy : null,
                match ($this->dmarcAlignmentVerification) {
                    DmarcAlignmentVerification::ALIGNED => 'Aligned',
                    DmarcAlignmentVerification::NOT_ALIGNED => 'Not aligned',
                    default => 'Alignment not verified',
                },
            ]),
        ];
    }

    protected function dmarcReportsDetail(?string $firstOpenId): array
    {
        $status = $this->dmarcStatus ?? [];
        $id = 'dns-dmarc-reports-detail';
        $ruaState = $status['rua_link_state'] ?? '';
        $lifecycle = $status['status'] ?? '';
        $dmarcUrl = $this->dmarcShowUrl();

        [$badgeVariant, $badgeLabel, $severity, $explanation, $primaryAction, $footer] = match (true) {
            $ruaState === DmarcStatusService::RUA_LINK_DETECTED_UNLINKED => [
                'warning',
                'Relink required',
                'warning',
                'MXScan reporting is present in DNS, but visibility data is not yet being collected for this domain.',
                ['label' => 'Fix reporting', 'href' => $dmarcUrl],
                null,
            ],
            $ruaState === DmarcStatusService::RUA_LINK_NOT_CONNECTED && ($status['has_rua'] ?? false) => [
                'warning',
                'Action required',
                'warning',
                'DMARC is active. Connect MXScan reporting to identify senders and authentication failures.',
                ['label' => 'Connect reporting', 'href' => $dmarcUrl],
                null,
            ],
            $lifecycle === DmarcStatusService::STATUS_ACTIVE => [
                'success',
                'Active',
                'success',
                $status['helper_text'] ?? 'Reports are being collected.',
                ['label' => 'Open DMARC visibility', 'href' => $dmarcUrl],
                $this->domain->dmarc_last_report_at
                    ? 'Last report: ' . $this->domain->dmarc_last_report_at->diffForHumans()
                    : null,
            ],
            $lifecycle === DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING => [
                'info',
                'Waiting',
                'neutral',
                $status['helper_text'] ?? 'Waiting for first report.',
                ['label' => 'Open DMARC visibility', 'href' => $dmarcUrl],
                null,
            ],
            default => [
                'neutral',
                $status['label'] ?? 'Not enabled',
                'neutral',
                'Add MXScan RUA to your DMARC record to receive aggregate reports.',
                ['label' => 'Set up reporting', 'href' => $dmarcUrl],
                null,
            ],
        };

        return [
            'id' => $id,
            'key' => 'dmarc_reports',
            'label' => 'DMARC Reports',
            'helpKey' => 'dmarc_reports',
            'badgeVariant' => $badgeVariant,
            'badgeLabel' => $badgeLabel,
            'severity' => $severity,
            'explanation' => $explanation,
            'open' => $id === $firstOpenId,
            'primaryAction' => $primaryAction,
            'type' => 'dmarc_reports',
            'footer' => $footer,
            'visibilityUrl' => $dmarcUrl,
        ];
    }

    protected function mxDetail(?string $firstOpenId): array
    {
        $card = $this->statusCards['mx'] ?? [];
        $analysis = MxAnalysisReader::analysis($this->mxInfo)
            ?? MxAnalysisReader::fromLegacyDnsRecord($this->records['MX'] ?? null, $this->mxInfo);
        $style = $this->mapState($card['state'] ?? null, ($this->records['MX']['status'] ?? '') === 'found');
        $id = 'dns-mx-detail';
        $rows = [];

        $targets = is_array($analysis['targets'] ?? null) ? $analysis['targets'] : [];
        foreach ($targets as $target) {
            $rows[] = [
                ['label' => 'Priority', 'value' => (string) ($target['preference'] ?? 'N/A')],
                ['label' => 'Host', 'value' => (string) ($target['normalized_hostname'] ?? $target['hostname'] ?? 'Unknown')],
                ['label' => 'Status', 'value' => (string) ($target['status'] ?? 'unknown')],
            ];
        }

        return [
            'id' => $id,
            'key' => 'mx',
            'label' => 'MX Records',
            'helpKey' => 'mx',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Unknown',
            'severity' => $style['severity'],
            'explanation' => $analysis['summary'] ?? ($card['status'] ?? 'MX configuration could not be evaluated.'),
            'open' => $id === $firstOpenId,
            'primaryAction' => null,
            'type' => 'mx',
            'rows' => $rows,
        ];
    }

    protected function tlsRptDetail(?string $firstOpenId): array
    {
        $data = $this->records['TLS-RPT'] ?? null;
        $card = $this->statusCards['tlsrpt'] ?? [];
        $found = ($data['status'] ?? '') === 'found';
        $style = $this->mapState($card['state'] ?? null, $found);
        $id = 'dns-tlsrpt-detail';
        $recordText = is_string($data['data'] ?? null) ? $data['data'] : null;

        return [
            'id' => $id,
            'key' => 'tlsrpt',
            'label' => 'TLS-RPT',
            'helpKey' => 'tlsrpt',
            'badgeVariant' => $found ? $style['variant'] : 'danger',
            'badgeLabel' => $found ? ($card['status'] ?? 'Configured') : 'Missing',
            'severity' => $found ? $style['severity'] : 'danger',
            'explanation' => $found
                ? ($card['status'] ?? 'A syntactically valid TLS-RPT destination is published.')
                : 'No TLS-RPT record found.',
            'open' => $id === $firstOpenId,
            'primaryAction' => $found && ($card['state'] ?? '') === ScanReportStatusMapper::PASS
                ? null
                : ['label' => $found ? 'Copy TLS-RPT record' : 'Add policy', 'href' => '#fix-pack'],
            'type' => 'code',
            'record' => $recordText,
        ];
    }

    protected function mtaStsDetail(?string $firstOpenId): array
    {
        $data = $this->records['MTA-STS'] ?? null;
        $card = $this->statusCards['mtasts'] ?? [];
        $found = ($data['status'] ?? '') === 'found';
        $style = $this->mapState($card['state'] ?? null, $found);
        $id = 'dns-mtasts-detail';

        return [
            'id' => $id,
            'key' => 'mtasts',
            'label' => 'MTA-STS',
            'helpKey' => 'mtasts',
            'badgeVariant' => $found ? $style['variant'] : 'danger',
            'badgeLabel' => $found ? ($card['status'] ?? 'Configured') : 'Missing',
            'severity' => $found ? $style['severity'] : 'danger',
            'explanation' => $found
                ? 'MTA-STS tells other mail servers to use secure encrypted delivery to your domain.'
                : 'No MTA-STS policy found.',
            'open' => $id === $firstOpenId,
            'primaryAction' => $found && ($card['state'] ?? '') === ScanReportStatusMapper::PASS
                ? null
                : ['label' => 'Add policy', 'href' => '#fix-pack'],
            'type' => 'code',
            'value' => $found ? (string) ($data['data'] ?? '') : null,
            'copyLabel' => 'Copy MTA-STS record',
            'footer' => $found ? ($card['status'] ?? null) : null,
        ];
    }

    /**
     * @param array<string, mixed>|null $data
     * @return array<string, mixed>
     */
    protected function simpleCodeDetail(
        string $id,
        string $key,
        string $label,
        string $helpKey,
        ?array $data,
        string $copyLabel,
        string $missingActionLabel,
        string $foundExplanation,
        string $missingExplanation,
        ?string $firstOpenId,
    ): array {
        $found = ($data['status'] ?? '') === 'found';

        return [
            'id' => $id,
            'key' => $key,
            'label' => $label,
            'helpKey' => $helpKey,
            'badgeVariant' => $found ? 'success' : 'danger',
            'badgeLabel' => $found ? 'Configured' : 'Missing',
            'severity' => $found ? 'success' : 'danger',
            'explanation' => $found ? $foundExplanation : $missingExplanation,
            'open' => $id === $firstOpenId,
            'primaryAction' => $found ? null : ['label' => $missingActionLabel, 'href' => '#fix-pack'],
            'type' => 'code',
            'value' => $found ? (string) ($data['data'] ?? '') : null,
            'copyLabel' => $copyLabel,
        ];
    }

    protected function bimiDetail(?string $firstOpenId): array
    {
        $data = $this->records['BIMI'] ?? null;
        $card = $this->statusCards['bimi'] ?? [];
        $analysis = BimiAnalysisReader::analysis($this->bimiInfo);
        $found = ($data['status'] ?? '') === 'found' || $analysis !== null;
        $style = $this->mapState($card['state'] ?? null, $found);
        $bimiPresenter = new BimiSectionPresenter(
            bimiInfo: $this->bimiInfo,
            legacyDnsRecord: $data,
            domain: $this->domain,
            scan: $this->scan,
        );
        $publicSummary = $bimiPresenter->publicSummary();

        $chips = [];
        if (is_array($publicSummary)) {
            if (!empty($publicSummary['readiness_status'])) {
                $chips[] = 'Readiness: ' . $publicSummary['readiness_status'];
            }
            if (!empty($publicSummary['logo_validation_status'])) {
                $chips[] = $bimiPresenter->logoValidationLabel($publicSummary['logo_validation_status']);
            }
            if (array_key_exists('dmarc_core_eligible', $publicSummary) && $publicSummary['dmarc_core_eligible'] !== null) {
                $chips[] = $publicSummary['dmarc_core_eligible'] ? 'DMARC core eligible' : 'DMARC core not eligible';
            }
        }

        $rawRecord = $found
            ? (string) ($analysis['record']['raw'] ?? $data['data']['raw_record'] ?? $data['data']['raw'] ?? '')
            : null;

        return [
            'id' => 'dns-bimi-detail',
            'key' => 'bimi',
            'label' => 'BIMI',
            'helpKey' => 'bimi',
            'badgeVariant' => $style['variant'],
            'badgeLabel' => $card['status'] ?? 'Optional',
            'severity' => $style['severity'],
            'explanation' => $card['subtext'] ?? ($publicSummary['summary'] ?? 'Branding readiness — does not affect Email Security Score.'),
            'open' => 'dns-bimi-detail' === $firstOpenId,
            'primaryAction' => null,
            'type' => 'bimi',
            'value' => $rawRecord !== '' ? $rawRecord : null,
            'copyLabel' => 'Copy BIMI record',
            'previewUrl' => $bimiPresenter->previewUrl(),
            'chips' => $chips,
        ];
    }
}
