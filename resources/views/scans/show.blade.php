@extends('layouts.app')

@section('page-title', 'Email security report')

@section('content')
@if(in_array($scan->status, ['queued', 'running', 'failed'], true))
<div class="mx-auto max-w-[1320px] px-6 lg:px-8">
    @include('scans.partials._pending-scan', ['scan' => $scan, 'domain' => $domain])
</div>
@else
@php
    $dnsPresenter = new \App\View\Presenters\DnsSectionPresenter(
        records: $records,
        statusCards: $statusCards ?? [],
        dmarcStatus: $dmarcStatus ?? null,
        spfLookupCount: $spfLookupCount ?? null,
        domain: $domain,
        dmarcPolicy: $dmarcPolicy,
        dmarcAligned: $dmarcAligned,
        dmarcAlignmentVerification: $dmarcAlignmentVerification ?? \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::NOT_VERIFIED,
        spfMax: $spfMax ?? 10,
        mxInfo: $resultData['mx'] ?? null,
        bimiInfo: $resultData['bimi'] ?? null,
        dkimInfo: $resultData['dkim'] ?? null,
        scan: $scan,
    );

    $techPresenter = new \App\View\Presenters\ReportTechnicalChecksPresenter(
        dns: $dnsPresenter,
        domain: $domain,
        blacklistHits: $blacklistHits,
        blacklistTotal: $blacklistTotal,
        domainDays: $domainDays,
        sslDays: $sslDays,
        blacklistEnabled: $enabled['blacklist'] ?? false,
        certificatesInfo: $resultData['certificates'] ?? null,
        mtaStsInfo: $resultData['mta_sts'] ?? null,
        scoreBreakdown: $scoreBreakdown ?? [],
        remediation: $technicalRemediation ?? [],
    );

    $techGroups = $techPresenter->groups();
    $scoredChecks = collect($techGroups)
        ->flatMap(fn ($group) => $group['items'] ?? [])
        ->reject(fn ($row) => ($row['optional'] ?? false) === true);
    $checkSummary = [
        'passing' => $scoredChecks->where('presentationState', 'passing')->count(),
        'needsAction' => $scoredChecks->where('presentationState', '!=', 'passing')->count(),
    ];

    $presenter = new \App\View\Presenters\ScanReportPresenter(
        domain: $domain,
        score: $scan->score,
        scoreDelta: $scoreDelta,
        statusCards: $statusCards ?? [],
        recommendations: $recommendations ?? [],
        allClear: $allClear ?? ['state' => 'needs_fixes'],
        scoreBreakdown: $scoreBreakdown ?? [],
        scoreTrend: $scoreTrend ?? ['labels' => [], 'scores' => []],
        blacklistHits: $blacklistHits,
        blacklistTotal: $blacklistTotal,
        dmarcPolicy: $dmarcPolicy,
        checkSummary: $checkSummary,
    );
@endphp

<x-report.container>
    <x-report.header :domain="$domain" :scan="$scan" :scan-url="route('domains.scan.now', $domain)" />

    @include('scans.partials._report-hero', ['presenter' => $presenter, 'score' => $scan->score, 'scoreDelta' => $scoreDelta])

    @include('scans.partials._auth-strip', ['presenter' => $presenter])

    @include('scans.partials._what-to-fix', ['presenter' => $presenter, 'allClear' => $allClear ?? ['state' => 'needs_fixes']])

    @if($enabled['dns'] ?? false)
        @include('scans.partials._score-breakdown-section', ['presenter' => $presenter, 'score' => $scan->score])
    @endif

    @if($enabled['dns'] ?? false)
        @include('scans.partials._technical-checks', [
            'techGroups' => $techGroups,
            'blacklistRows' => $blacklistRows,
            'enabled' => $enabled,
            'domain' => $domain,
            'scan' => $scan,
            'technicalRemediation' => $technicalRemediation ?? [],
        ])
    @endif

    @include('scans.partials._score-history', [
        'presenter' => $presenter,
        'scan' => $scan,
        'domain' => $domain,
        'scoreTrend' => $scoreTrend ?? ['labels' => [], 'scores' => []],
    ])

    @include('scans.partials._report-secondary', [
        'domain' => $domain,
        'scan' => $scan,
        'incidents' => $incidents,
        'domainDays' => $domainDays,
        'sslDays' => $sslDays,
        'cadence' => $cadence,
        'enabled' => $enabled,
        'deliveries' => $deliveries,
    ])

    <div class="pt-2">
        <a href="{{ route('dashboard.domains') }}" class="inline-flex items-center text-sm text-gray-600 hover:text-gray-900">
            <svg class="mr-2 h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
            </svg>
            Back to Domain Management
        </a>
    </div>
</x-report.container>

<script>
    function copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const copiedLabel = button.dataset.copiedLabel || 'Copied!';
            const copyLabel = button.dataset.copyLabel || button.getAttribute('aria-label') || 'Copy value';
            const textLabel = button.querySelector('[data-copy-text]');
            const feedback = button.querySelector('[data-copy-feedback]');
            button.setAttribute('aria-label', copiedLabel);
            button.title = copiedLabel;
            if (textLabel) textLabel.textContent = copiedLabel;
            if (feedback) feedback.textContent = copiedLabel;
            setTimeout(() => {
                button.setAttribute('aria-label', copyLabel);
                button.title = copyLabel;
                if (textLabel) textLabel.textContent = copyLabel;
                if (feedback) feedback.textContent = '';
            }, 1500);
        }).catch(() => {
            button.setAttribute('aria-label', 'Copy failed');
            const feedback = button.querySelector('[data-copy-feedback]');
            if (feedback) feedback.textContent = 'Copy failed';
            setTimeout(() => {
                button.setAttribute('aria-label', button.dataset.copyLabel || 'Copy value');
                if (feedback) feedback.textContent = '';
            }, 1500);
        });
    }

    function shareReport() {
        alert('Share functionality coming soon!');
    }

    document.addEventListener('DOMContentLoaded', function() {
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    });
</script>
@endif
@endsection
