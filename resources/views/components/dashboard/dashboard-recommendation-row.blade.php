@props(['recommendation'])

<article class="dashboard-recommendation-row">
    <div class="dashboard-recommendation-rank" aria-label="Priority {{ $recommendation['rank'] }}">
        {{ $recommendation['rank'] }}
    </div>
    <div class="dashboard-recommendation-copy">
        <div class="dashboard-recommendation-heading">
            <h3>{{ $recommendation['title'] }}</h3>
            <x-report.severity-badge
                :severity="$recommendation['severity']"
                :label="ucfirst($recommendation['severity']) . ' priority'"
            />
        </div>
        @if($recommendation['score_impact'])
            <x-report.score-impact :label="$recommendation['score_impact']" />
        @endif
        <p>{{ $recommendation['explanation'] }}</p>
    </div>
    <a href="{{ $recommendation['action_url'] }}" class="mx-btn mx-btn-secondary dashboard-recommendation-button">
        {{ $recommendation['action_label'] }}
    </a>
</article>
