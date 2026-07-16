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
    'state' => null,
    'severity' => 'neutral',
    'lostPoints' => null,
    'scoreLabel' => null,
    'optional' => false,
])

@php
    $state = $state ?? (in_array($badgeVariant, ['danger', 'warning'], true) ? 'failing' : 'passing');
@endphp

<details id="{{ $id }}"
         {{ $open ? 'open' : '' }}
         class="mx-tech-check-row mx-tech-check-row--{{ $state }} group"
         data-tech-check
         data-presentation-state="{{ $state }}"
         x-data="{ expanded: {{ $open ? 'true' : 'false' }} }"
         @toggle="expanded = $el.open">
    <summary class="mx-tech-check-summary"
             aria-controls="{{ $id }}-panel"
             :aria-expanded="expanded.toString()">
        <span class="mx-tech-check-icon" aria-hidden="true">
            <i data-lucide="{{ $icon }}" class="h-4 w-4"></i>
        </span>

        <div class="mx-tech-check-main">
            <span class="mx-tech-check-title">{{ $label }}</span>
            <span class="mx-tech-check-desc">{{ $result }}</span>
        </div>

        <div class="mx-tech-check-status-slot">
            <x-report.status-pill :variant="$badgeVariant" :label="$optional ? ('Optional · ' . $badgeLabel) : $badgeLabel" />
        </div>

        <div class="mx-tech-check-meta-slot">
            @if($lostPoints)
                @if($scoreLabel)<span class="mx-tech-score-label">{{ $scoreLabel }}</span>@endif
                <strong class="mx-tech-lost-points">−{{ $lostPoints }} pts</strong>
            @elseif($scoreLabel)
                <span class="mx-tech-score-label">{{ $scoreLabel }}</span>
            @else
                {{ $metadata }}
            @endif
        </div>

        <div class="mx-tech-check-action-slot">
            @if($action && $state !== 'failing')
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
                @if($lostPoints)
                    @if($scoreLabel)<span class="mx-tech-score-label">{{ $scoreLabel }}</span>@endif
                    <strong class="mx-tech-lost-points">−{{ $lostPoints }} pts</strong>
                @elseif($scoreLabel)
                    <span class="mx-tech-score-label">{{ $scoreLabel }}</span>
                @endif
                @if($metadata)
                    <span class="text-xs text-gray-500">{{ $metadata }}</span>
                @endif
                @if($action && $state !== 'failing')
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

    <div id="{{ $id }}-panel" class="mx-tech-check-detail" role="region" aria-label="{{ $label }} details">
        {{ $slot }}
    </div>
</details>
