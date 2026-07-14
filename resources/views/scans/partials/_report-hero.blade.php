@php
    $scoreMeta = $presenter->scoreMeta();
    $finding = $presenter->primaryFinding();
@endphp

<section class="rounded-2xl border border-gray-200/80 bg-white p-5 shadow-sm lg:grid lg:grid-cols-[34%_66%] lg:gap-8 lg:p-6">
    <x-report.score-ring
        :score="$score"
        :percent="$scoreMeta['percent']"
        :label="$scoreMeta['label']"
        :supporting="$scoreMeta['supporting']"
        :subtitle="$scoreMeta['subtitle']"
        :delta="$scoreDelta"
    />
    <x-report.primary-finding :finding="$finding" />
</section>
