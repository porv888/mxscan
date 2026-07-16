@props(['presenter', 'score', 'scoreDelta' => null])

@php
    $scoreMeta = $presenter->scoreMeta();
    $finding = $presenter->primaryFinding();
    $summary = $presenter->reportSummary();
@endphp

<section class="report-hero" aria-labelledby="report-overall-state">
    <x-report.score-ring
        :score="$score"
        :percent="$scoreMeta['percent']"
        :label="$scoreMeta['label']"
        :supporting="$scoreMeta['supporting']"
        :subtitle="$scoreMeta['subtitle']"
        :delta="$scoreDelta"
    />

    <div class="report-hero-summary" aria-label="Report summary">
        <p class="report-eyebrow">Report summary</p>
        <h2 id="report-overall-state">{{ $scoreMeta['label'] }}</h2>
        <dl>
            <div><dt>Checks passing</dt><dd>{{ $summary['passing'] }}</dd></div>
            <div><dt>Checks needing action</dt><dd>{{ $summary['needsAction'] }}</dd></div>
            <div><dt>Email security score</dt><dd>{{ $score ?? '—' }} / 100</dd></div>
        </dl>
    </div>

    <x-report.report-priority-card :finding="$finding" />
</section>
