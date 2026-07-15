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
    <summary class="mx-tech-check-summary [&::-webkit-details-marker]:hidden"
             aria-controls="{{ $id }}-panel">
        <span class="mx-tech-check-icon" aria-hidden="true">
            <i data-lucide="{{ $icon }}" class="h-4 w-4"></i>
        </span>

        <div class="mx-tech-check-name-block">
            <div class="min-w-0">
                <span class="block text-sm font-semibold leading-[1.35] text-gray-900">{{ $label }}</span>
                <span class="mt-1 block text-[13px] leading-[1.5] text-gray-500">{{ $result }}</span>
            </div>
            <div class="mx-tech-check-status-col">
                <x-report.status-pill :variant="$badgeVariant" :label="$badgeLabel" />
            </div>
        </div>

        @if($metadata)
            <div class="mx-tech-check-meta-col hidden md:block">{{ $metadata }}</div>
        @else
            <div class="mx-tech-check-meta-col hidden md:block" aria-hidden="true"></div>
        @endif

        <div class="mx-tech-check-action-col hidden md:block">
            @if($action)
                <a href="{{ $action['href'] ?? '#' }}"
                   class="text-sm font-medium text-blue-700 hover:text-blue-800 hover:underline"
                   @if(str_starts_with($action['href'] ?? '', '#')) onclick="event.stopPropagation();" @endif>
                    {{ $action['label'] }}
                </a>
            @endif
        </div>

        <div class="mx-tech-check-chevron-col hidden md:flex">
            <svg class="mx-tech-check-chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
            </svg>
        </div>

        <div class="mx-tech-check-action-row md:hidden">
            <div class="flex items-center gap-3">
                @if($metadata)
                    <span class="text-xs text-gray-500">{{ $metadata }}</span>
                @endif
                @if($action)
                    <a href="{{ $action['href'] ?? '#' }}"
                       class="min-h-[44px] inline-flex items-center text-sm font-medium text-blue-700 hover:text-blue-800"
                       @if(str_starts_with($action['href'] ?? '', '#')) onclick="event.stopPropagation();" @endif>
                        {{ $action['label'] }}
                    </a>
                @endif
            </div>
            <svg class="mx-tech-check-chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
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
