@php
    $coreRecs = $presenter->coreRecommendations();
    $optionalRecs = $presenter->optionalRecommendations();
    $clearState = $allClear['state'] ?? 'needs_fixes';
    $severitySummary = $presenter->severitySummary();
@endphp

<section id="what-to-fix"
         class="space-y-4"
         x-data="{ expanded: 0, showAll: false, toggle(i) { this.expanded = this.expanded === i ? -1 : i; } }">
    <div>
        <h2 class="mx-report-section-title">What to fix</h2>
        <p class="mx-report-section-subtitle">Resolve the highest-impact issues first.</p>

        @if($clearState !== 'all_clear' && $coreRecs !== [])
            <div class="mt-3 flex flex-wrap gap-2">
                @if($severitySummary['critical'] > 0)
                    <span class="mx-chip">{{ $severitySummary['critical'] }} critical</span>
                @endif
                @if($severitySummary['high'] > 0)
                    <span class="mx-chip">{{ $severitySummary['high'] }} high priority</span>
                @endif
                @if($severitySummary['medium'] > 0)
                    <span class="mx-chip">{{ $severitySummary['medium'] }} medium priority</span>
                @endif
                @if($severitySummary['low'] > 0)
                    <span class="mx-chip">{{ $severitySummary['low'] }} low priority</span>
                @endif
                @if($severitySummary['optional'] > 0)
                    <span class="mx-chip">{{ $severitySummary['optional'] }} informational</span>
                @endif
            </div>
        @endif
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
        <div class="space-y-3 lg:space-y-4">
            @foreach($coreRecs as $index => $rec)
                <div x-show="showAll || {{ $index }} < 3" data-recommendation-item>
                    <x-report.recommendation-card
                        :index="$index"
                        :rec="$rec"
                        :impact="$presenter->impactForKey($rec['key'] ?? '')"
                        :category="$presenter->categoryForRecommendationKey($rec['key'] ?? '')"
                        :endpoint="$presenter->endpointMetadataForRecommendation($rec)"
                        :score-opportunity="$presenter->scoreOpportunityForKey($rec['key'] ?? '')"
                    />
                </div>
            @endforeach
        </div>

        @if(count($coreRecs) > 3)
            <button type="button"
                    class="min-h-[44px] text-sm font-medium text-blue-700 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    @click="showAll = !showAll"
                    x-text="showAll ? 'Show fewer recommendations' : 'Show all recommendations ({{ count($coreRecs) }})'">
            </button>
        @endif
    @endif

    @if($optionalRecs !== [])
        <div class="rounded-xl border border-gray-200 bg-white p-4 lg:p-5">
            <h3 class="text-sm font-semibold text-gray-900">Optional improvements</h3>
            <ul class="mt-3 space-y-2">
                @foreach($optionalRecs as $rec)
                    <li class="text-[13px] leading-[1.5] text-gray-600">{{ $rec['title'] }} — {{ $rec['explanation'] }}</li>
                @endforeach
            </ul>
        </div>
    @endif
</section>
