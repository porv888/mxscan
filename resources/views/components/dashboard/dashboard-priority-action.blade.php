@props(['recommendation'])

@if($recommendation)
<section class="dashboard-priority-action" aria-labelledby="dashboard-fix-first">
    <div class="dashboard-priority-action-copy">
        <p class="dashboard-eyebrow">Highest-impact action for your domain</p>
        <h2 id="dashboard-fix-first">{{ $recommendation['issue_title'] }}</h2>
        <div class="dashboard-priority-meta">
            <x-report.severity-badge
                :severity="$recommendation['severity']"
                :label="ucfirst($recommendation['severity']) . ' priority'"
            />
            @if($recommendation['score_impact'])
                <x-report.score-impact :label="$recommendation['score_impact']" />
            @endif
        </div>
        <p>{{ $recommendation['key'] === 'spf_missing'
            ? 'Publish an SPF TXT record listing every service that sends email for ' . $recommendation['domain'] . '.'
            : $recommendation['explanation'] }}</p>
    </div>
    <div class="dashboard-priority-action-buttons">
        <a href="{{ $recommendation['action_url'] }}" class="mx-btn mx-btn-primary">
            {{ $recommendation['action_label'] }}
        </a>
        <a href="{{ $recommendation['evidence_url'] }}" class="mx-btn mx-btn-secondary">View evidence</a>
    </div>
</section>
@endif
