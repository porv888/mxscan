@props([
    'label',
    'badgeVariant' => 'neutral',
    'badgeLabel',
    'summary',
    'severity' => 'neutral',
    'accent' => '',
    'primaryAction' => null,
    'detailId' => null,
])

<div {{ $attributes->merge(['class' => "flex h-full min-w-0 flex-col rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800/50 {$accent}"]) }}>
    <div class="mb-2 flex items-start justify-between gap-2">
        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100">{{ $label }}</h4>
        <x-dns.status-badge :variant="$badgeVariant" :label="$badgeLabel" />
    </div>
    <p class="mb-3 flex-1 text-xs leading-5 text-gray-600 dark:text-gray-400">{{ $summary }}</p>
    <div class="flex flex-wrap items-center gap-2">
        @if($primaryAction)
            <a href="{{ $primaryAction['href'] }}" class="mx-btn mx-btn-primary mx-btn-sm">{{ $primaryAction['label'] }}</a>
        @endif
        @if($detailId)
            <a href="#{{ $detailId }}"
               class="mx-btn mx-btn-ghost mx-btn-sm"
               onclick="document.getElementById('{{ $detailId }}')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); const el = document.getElementById('{{ $detailId }}'); if (el && !el.open) el.open = true;">
                View details
            </a>
        @endif
    </div>
</div>
