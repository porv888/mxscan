@php
    use App\View\Presenters\ScanReportPresenter;

    $coreRecs = $presenter->coreRecommendations();
    $optionalRecs = $presenter->optionalRecommendations();
    $clearState = $allClear['state'] ?? 'needs_fixes';
@endphp

<section id="what-to-fix" class="space-y-4" x-data="{ expanded: 0, showAll: false, toggle(i) { this.expanded = this.expanded === i ? -1 : i; } }">
    <div>
        <h2 class="text-xl font-semibold text-gray-900">What to fix</h2>
        <p class="mt-1 text-sm text-gray-600">Resolve these issues in order of security impact.</p>
    </div>

    @if($clearState === 'all_clear')
        <div class="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
            <h3 class="text-base font-semibold text-gray-900">All clear</h3>
            <p class="mt-2 text-sm text-gray-600">{{ $allClear['message'] ?? 'No critical fixes needed.' }}</p>
        </div>
    @elseif($coreRecs === [])
        <div class="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
            <p class="text-sm text-gray-600">No prioritized recommendations for this scan.</p>
        </div>
    @else
        <div class="space-y-3">
            @foreach($coreRecs as $index => $rec)
                <div x-show="showAll || {{ $index }} < 3">
                    <x-report.recommendation-card
                        :index="$index"
                        :rec="$rec"
                        :impact="$presenter->impactForKey($rec['key'] ?? '')"
                    />
                </div>
            @endforeach
        </div>

        @if(count($coreRecs) > 3)
            <button type="button" class="text-sm font-medium text-blue-700 hover:underline" @click="showAll = !showAll" x-text="showAll ? 'Show fewer recommendations' : 'Show all recommendations ({{ count($coreRecs) }})'"></button>
        @endif
    @endif

    @if($optionalRecs !== [])
        <div class="rounded-xl border border-gray-200 bg-white p-4">
            <h3 class="text-sm font-semibold text-gray-900">Optional improvements</h3>
            <ul class="mt-2 space-y-1">
                @foreach($optionalRecs as $rec)
                    <li class="text-sm text-gray-600">{{ $rec['title'] }} — {{ $rec['explanation'] }}</li>
                @endforeach
            </ul>
        </div>
    @endif
</section>
