@props([
    'label',
    'icon' => 'folder',
    'summary' => null,
    'statusVariant' => null,
    'statusLabel' => null,
])

<article {{ $attributes->merge(['class' => 'mx-tech-category-card', 'data-tech-category' => true]) }}>
    <header class="mx-tech-category-header">
        <div class="flex min-w-0 items-center gap-3">
            <span class="mx-tech-check-icon" aria-hidden="true">
                <i data-lucide="{{ $icon }}" class="h-4 w-4"></i>
            </span>
            <div class="min-w-0">
                <h3 class="text-[15px] font-semibold leading-[1.35] text-gray-900">{{ $label }}</h3>
                @if($summary)
                    <p class="mt-0.5 text-xs leading-5 text-gray-500">{{ $summary }}</p>
                @endif
            </div>
        </div>
        @if($statusVariant && $statusLabel)
            <x-report.status-pill :variant="$statusVariant" :label="$statusLabel" />
        @endif
    </header>

    <div class="divide-y divide-gray-100">
        {{ $slot }}
    </div>
</article>
