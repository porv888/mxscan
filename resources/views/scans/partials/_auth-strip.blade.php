@php
    $items = $presenter->authStripItems();
@endphp

<section aria-label="Authentication summary">
    <div class="report-summary-grid">
        @foreach($items as $item)
            <x-report.report-summary-card
                :icon="$item['icon']"
                :label="$item['label']"
                :status="$item['status']"
                :explanation="$item['explanation']"
                :variant="$item['variant']"
                :target="$item['target']"
                :score="$item['score']"
            />
        @endforeach
    </div>
</section>
