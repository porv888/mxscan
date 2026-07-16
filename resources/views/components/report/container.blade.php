@props(['maxWidth' => 'max-w-[1320px]'])

<div {{ $attributes->merge(['class' => $maxWidth . ' mx-auto w-full min-w-0 space-y-6']) }}>
    {{ $slot }}
</div>
