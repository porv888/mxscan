@php
    $rows = $presenter->scoreBreakdownRows();
    $earnedTotal = $presenter->scoreEarnedTotal();
@endphp

<section class="rounded-2xl border border-gray-200/80 bg-white p-5 shadow-sm lg:p-6">
    <div class="flex items-start justify-between gap-4">
        <div>
            <h2 class="text-xl font-semibold text-gray-900">Score breakdown</h2>
            <p class="mt-1 text-sm text-gray-600">Points earned toward authentication and transport-security configuration.</p>
        </div>
        <div class="text-lg font-semibold text-gray-900">{{ $score ?? $earnedTotal }} / 100</div>
    </div>

    <div class="mt-5 divide-y divide-gray-100">
        @foreach($rows as $row)
            <x-report.score-breakdown-row
                :label="$row['label']"
                :earned="$row['earned']"
                :possible="$row['possible']"
                :status="$row['status'] ?? 'ok'"
            />
            @foreach($row['subcomponents'] ?? [] as $subcomponent)
                <div class="ml-4 border-l-2 border-gray-100 pl-4">
                    <x-report.score-breakdown-row
                        :label="$subcomponent['label']"
                        :earned="$subcomponent['earned']"
                        :possible="$subcomponent['possible']"
                        :status="$subcomponent['status'] ?? 'ok'"
                    />
                </div>
            @endforeach
        @endforeach
    </div>

    @if($earnedTotal < 100)
        <p class="mt-4 text-[13px] text-gray-500">
            Earned {{ $earnedTotal }} of 100 possible points (capped at 100). Historical scans may use an older scoring model.
        </p>
    @endif
</section>
