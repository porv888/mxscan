@php
    $items = $presenter->authStripItems();
@endphp

<section class="overflow-hidden rounded-2xl border border-gray-200/80 bg-white shadow-sm">
    <div class="grid grid-cols-1 divide-y lg:grid-cols-4 lg:divide-x lg:divide-y-0">
        @foreach($items as $item)
            <x-report.auth-strip-item
                :icon="$item['icon']"
                :label="$item['label']"
                :status="$item['status']"
                :explanation="$item['explanation']"
                :variant="$item['variant']"
            />
        @endforeach
    </div>
</section>
