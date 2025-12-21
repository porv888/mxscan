@props(['verdict'])

@php
$configs = [
    'ok' => [
        'color' => 'bg-green-100 text-green-800',
        'icon' => 'check-circle',
        'label' => 'OK',
    ],
    'warning' => [
        'color' => 'bg-yellow-100 text-yellow-800',
        'icon' => 'alert-triangle',
        'label' => 'Warning',
    ],
    'incident' => [
        'color' => 'bg-red-100 text-red-800',
        'icon' => 'alert-circle',
        'label' => 'Incident',
    ],
];

$config = $configs[$verdict] ?? $configs['ok'];
@endphp

<span {{ $attributes->merge(['class' => "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium {$config['color']}"]) }}>
    <i data-lucide="{{ $config['icon'] }}" class="w-3 h-3 mr-1"></i>{{ $config['label'] }}
</span>
