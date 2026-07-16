@props([
    'id',
    'icon',
    'label',
    'badgeVariant' => 'neutral',
    'badgeLabel',
    'result',
    'action' => null,
    'metadata' => null,
    'open' => false,
])

<details id="{{ $id }}" {{ $open ? 'open' : '' }} class="mx-tech-check-row group" data-tech-check>
    <summary class="mx-tech-check-summary"
             aria-controls="{{ $id }}-panel">
        <span class="mx-tech-check-icon" aria-hidden="true">
            <i data-lucide="{{ $icon }}" class="h-4 w-4"></i>
        </span>

        <div class="mx-tech-check-main">
            <span class="mx-tech-check-title">{{ $label }}</span>
            <span class="mx-tech-check-desc">{{ $result }}</span>
        </div>

        <div class="mx-tech-check-status-slot">
            <x-report.status-pill :variant="$badgeVariant" :label="$badgeLabel" />
        </div>

        <div class="mx-tech-check-meta-slot">
            {{ $metadata }}
        </div>

        <div class="mx-tech-check-action-slot">
            @if($action)
                <a href="{{ $action['href'] ?? '#' }}"
                   class="mx-tech-check-action text-sm font-medium text-blue-700 hover:text-blue-800 hover:underline"
                   @if(str_starts_with($action['href'] ?? '', '#')) onclick="event.stopPropagation();" @endif>
                    {{ $action['label'] }}
                </a>
            @endif
        </div>

        <div class="mx-tech-check-chevron-slot" aria-hidden="true">
            <svg class="mx-tech-check-chevron" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
            </svg>
        </div>

        <div class="mx-tech-check-mobile-bar">
            <div class="flex min-w-0 flex-1 items-center gap-3">
                @if($metadata)
                    <span class="text-xs text-gray-500">{{ $metadata }}</span>
                @endif
                @if($action)
                    <a href="{{ $action['href'] ?? '#' }}"
                       class="mx-tech-check-action min-h-[44px] inline-flex items-center text-sm font-medium text-blue-700 hover:text-blue-800"
                       @if(str_starts_with($action['href'] ?? '', '#')) onclick="event.stopPropagation();" @endif>
                        {{ $action['label'] }}
                    </a>
                @endif
            </div>
            <svg class="mx-tech-check-chevron" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
            </svg>
        </div>
    </summary>

    <div id="{{ $id }}-panel" class="pb-1" role="region" aria-label="{{ $label }} details">
        <x-report.evidence-panel>
            {{ $slot }}
        </x-report.evidence-panel>
    </div>
</details>
