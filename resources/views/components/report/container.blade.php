@props(['maxWidth' => 'max-w-[1320px]'])

<div {{ $attributes->merge(['class' => 'max-w-[1320px] mx-auto w-full px-6 lg:px-8 space-y-6']) }}>
    {{ $slot }}
</div>
