@props([
    'finding',
])

@if($finding)
<div {{ $attributes->merge(['class' => 'flex h-full flex-col justify-center']) }}>
    @if(($finding['severity'] ?? '') !== 'success')
        <p class="text-[13px] font-medium uppercase tracking-wide text-gray-500">Highest-priority issue</p>
    @endif

    <div class="mt-2 flex flex-wrap items-center gap-2">
        <h2 class="text-2xl font-semibold text-gray-900">{{ $finding['title'] }}</h2>
        <x-report.status-badge :variant="$finding['severity'] === 'success' ? 'success' : ($finding['severity'] === 'critical' ? 'danger' : ($finding['severity'] === 'high' ? 'warning' : 'info'))" :label="$finding['badge']" />
    </div>

    <p class="mt-3 text-sm leading-6 text-gray-600 lg:text-base">{{ $finding['explanation'] }}</p>

    @if(!empty($finding['impact']))
        <p class="mt-2 text-sm text-gray-500"><span class="font-medium text-gray-700">Impact:</span> {{ $finding['impact'] }}</p>
    @endif

    <div class="mt-5 flex flex-wrap items-center gap-3">
        @if(!empty($finding['cta']))
            <a href="{{ $finding['ctaHref'] ?? '#what-to-fix' }}" class="mx-btn mx-btn-primary">{{ $finding['cta'] }}</a>
        @endif
        @if(!empty($finding['whyHref']))
            <a href="{{ $finding['whyHref'] }}{{ !empty($finding['technicalTarget']) ? '' : '' }}"
               @if(!empty($finding['technicalTarget']))
               onclick="event.preventDefault(); const el = document.getElementById('{{ $finding['technicalTarget'] }}'); if (el) { el.open = true; el.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }"
               @endif
               class="text-sm font-medium text-blue-700 hover:underline">
                Why this matters
            </a>
        @endif
    </div>
</div>
@endif
