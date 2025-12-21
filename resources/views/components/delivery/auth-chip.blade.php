@props(['value', 'label'])

@php
// Map nullable boolean to status string
$status = is_null($value) ? 'none' : ($value ? 'pass' : 'fail');

$colors = [
    'pass' => 'bg-green-50 text-green-700',
    'fail' => 'bg-red-50 text-red-700',
    'none' => 'bg-gray-50 text-gray-500',
];

$icons = [
    'pass' => 'check',
    'fail' => 'x',
    'none' => 'minus',
];

$color = $colors[$status];
$icon = $icons[$status];
$text = ucfirst($status);
@endphp

<span {{ $attributes->merge(['class' => "inline-flex items-center px-2 py-1 rounded-md text-xs font-medium {$color}"]) }}>
    {{ $label }}
    <span class="ml-2">— {{ $text }}</span>
</span>
