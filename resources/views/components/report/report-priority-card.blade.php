@props(['finding'])

@if($finding)
<article class="report-priority-card">
    <p class="report-eyebrow">{{ ($finding['severity'] ?? '') === 'success' ? 'Current state' : 'Highest-priority issue' }}</p>
    <div class="report-priority-heading">
        <h2>{{ $finding['title'] }}</h2>
        <x-report.severity-badge :severity="$finding['severity'] ?? 'medium'" />
    </div>

    @if(!empty($finding['scoreImpact']))
        <x-report.score-impact :label="$finding['scoreImpact']" class="mt-2" />
    @endif

    <p class="report-priority-explanation">{{ $finding['explanation'] }}</p>

    <div class="report-priority-actions">
        @if(!empty($finding['cta']))
            <a href="{{ $finding['ctaHref'] }}" class="mx-btn mx-btn-primary">{{ $finding['cta'] }}</a>
        @endif
        @if(!empty($finding['whyHref']))
            <a href="{{ $finding['whyHref'] }}"
               @if(!empty($finding['technicalTarget']))
               onclick="event.preventDefault(); const el = document.getElementById('{{ $finding['technicalTarget'] }}'); if (el) { el.open = true; el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }"
               @endif
               class="mx-btn mx-btn-secondary">
                View evidence
            </a>
        @endif
    </div>
</article>
@endif
