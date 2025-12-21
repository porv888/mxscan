@props(['status' => 'not-checked', 'count' => 0, 'size' => 'sm'])

@php
    $statusConfig = [
        'clean' => [
            'bg' => 'bg-green-100',
            'text' => 'text-green-800',
            'icon' => '🟢',
            'label' => 'Clean'
        ],
        'listed' => [
            'bg' => 'bg-red-100',
            'text' => 'text-red-800',
            'icon' => '🔴',
            'label' => $count > 1 ? "Listed ({$count})" : 'Listed'
        ],
        'not-checked' => [
            'bg' => 'bg-gray-100',
            'text' => 'text-gray-600',
            'icon' => '⚪',
            'label' => 'Not checked'
        ],
        'checking' => [
            'bg' => 'bg-blue-100',
            'text' => 'text-blue-800',
            'icon' => '🔄',
            'label' => 'Checking...'
        ]
    ];
    
    $config = $statusConfig[$status] ?? $statusConfig['not-checked'];
    $sizeClasses = $size === 'lg' ? 'px-3 py-1.5 text-sm' : 'px-2.5 py-0.5 text-xs';
@endphp

<span {{ $attributes->merge(['class' => "inline-flex items-center {$sizeClasses} rounded-full font-medium {$config['bg']} {$config['text']}"]) }}>
    <span class="mr-1">{{ $config['icon'] }}</span>
    {{ $config['label'] }}
</span>