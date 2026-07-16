@props(['metric'])

<article class="dashboard-metric-card dashboard-metric-card--{{ $metric['state'] }}">
    <div class="dashboard-metric-header">
        <span class="dashboard-metric-icon" aria-hidden="true">
            <i data-lucide="{{ $metric['icon'] }}"></i>
        </span>
        <h3>{{ $metric['title'] }}</h3>
    </div>
    <p class="dashboard-metric-value">{{ $metric['value'] }}</p>
    <p class="dashboard-metric-description">{{ $metric['description'] }}</p>
    @if($metric['action_label'])
        <a href="{{ $metric['action_url'] }}" class="dashboard-metric-action">
            {{ $metric['action_label'] }}
            <i data-lucide="arrow-right" aria-hidden="true"></i>
        </a>
    @endif
</article>
