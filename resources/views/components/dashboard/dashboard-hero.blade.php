@props(['hero'])

@if($hero)
<section class="dashboard-hero" aria-labelledby="dashboard-latest-score">
    <div class="dashboard-hero-score">
        <p class="dashboard-eyebrow">Latest security score</p>
        <div class="dashboard-score-value" id="dashboard-latest-score">
            {{ $hero['score'] }} <span>/ 100</span>
        </div>
        <p class="dashboard-score-status">{{ $hero['status'] }}</p>
        <div class="dashboard-score-progress" role="img" aria-label="Security score {{ $hero['score'] }} out of 100">
            <span style="width: {{ max(0, min(100, $hero['score'])) }}%"></span>
        </div>
        <p class="dashboard-domain">{{ $hero['domain'] }}</p>
        <p class="dashboard-scan-date">
            Scanned {{ $hero['scanned_at']->timezone(auth()->user()->timezone ?? 'UTC')->format('j F Y \a\t H:i') }}
        </p>
    </div>

    <div class="dashboard-hero-priority">
        <p class="dashboard-eyebrow">Highest-priority issue</p>
        @if($hero['priority'])
            <h2>{{ $hero['priority']['issue_title'] }}</h2>
            <p>{{ $hero['priority']['explanation'] }}</p>
            <div class="dashboard-priority-meta">
                <x-report.severity-badge
                    :severity="$hero['priority']['severity']"
                    :label="ucfirst($hero['priority']['severity']) . ' priority'"
                />
                @if($hero['priority']['score_impact'])
                    <x-report.score-impact :label="$hero['priority']['score_impact']" />
                @endif
            </div>
        @else
            <h2>No priority findings</h2>
            <p>The latest scan did not identify an immediate configuration action.</p>
        @endif
    </div>

    <div class="dashboard-hero-actions">
        @if($hero['priority'])
            <a href="{{ $hero['priority']['action_url'] }}" class="mx-btn mx-btn-primary">
                {{ $hero['priority']['action_label'] }}
            </a>
        @endif
        <a href="{{ $hero['report_url'] }}" class="mx-btn mx-btn-secondary">View full report</a>
    </div>
</section>
@endif
