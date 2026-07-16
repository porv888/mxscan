@props([
    'index',
    'rec',
    'impact' => null,
    'category' => null,
    'endpoint' => null,
    'scoreOpportunity' => null,
])

@php
    $severity = $rec['severity'] ?? 'medium';
    $cardModifier = match ($severity) {
        'critical' => 'mx-recommendation-card--critical',
        'high' => 'mx-recommendation-card--high',
        default => '',
    };
@endphp

<article class="mx-recommendation-card {{ $cardModifier }}" data-recommendation-card>
    <button type="button"
            @click="toggle({{ $index }})"
            class="mx-recommendation-card-header"
            :aria-expanded="expanded === {{ $index }}"
            aria-controls="rec-panel-{{ $index }}">
        <div class="mx-recommendation-rank">
            <span class="mx-recommendation-priority" aria-label="Priority {{ $index + 1 }}">{{ $index + 1 }}</span>
            <x-report.severity-badge :severity="$severity" />
        </div>

        <div class="min-w-0">
            <h3>{{ $rec['title'] }}</h3>
            @if($endpoint)
                <x-report.endpoint-badge :category="$endpoint['category']" :endpoint="$endpoint['endpoint']" class="mt-1" />
            @elseif($category)
                <p class="mx-recommendation-category">{{ $category }}</p>
            @endif
            <p class="mx-recommendation-summary" x-show="expanded !== {{ $index }}">{{ $rec['explanation'] }}</p>
            @if($scoreOpportunity)
                <x-report.score-impact :label="$scoreOpportunity" class="mt-2" />
            @endif
            @if($rec['locked'] ?? false)
                <p class="report-warning-panel mt-2" role="status">Locked until SPF and DKIM alignment are verified.</p>
            @endif
        </div>

        <div class="mx-recommendation-action">
            @if(!empty($rec['action']) && ($rec['actionable'] ?? true))
                <span>{{ $rec['action'] }}</span>
            @endif
            <svg :class="{ 'rotate-180': expanded === {{ $index }} }" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
        </div>
    </button>

    <div id="rec-panel-{{ $index }}"
         x-show="expanded === {{ $index }}"
         x-collapse
         class="mx-recommendation-expanded"
         role="region"
         aria-label="{{ $rec['title'] }} details">
        <div class="mx-recommendation-detail-grid">
            <section>
                <h4>Why this matters</h4>
                <p>{{ $rec['explanation'] }}</p>
                @if($impact)<p>{{ $impact }}</p>@endif
            </section>

            <section>
                <h4>Evidence</h4>
                @if(!empty($rec['value']))
                    <x-report.code-value
                        :value="$rec['value']"
                        record-type="TXT"
                        :record-host="$rec['record_name'] ?? '@'"
                        :copy-label="'Copy ' . ($rec['title'] ?? 'record')"
                    />
                @else
                    <p>Open the matching technical check for its DNS, endpoint, or verification evidence.</p>
                @endif
            </section>

            <section>
                <h4>Exact solution</h4>
                @if($rec['locked'] ?? false)
                    <p class="report-warning-panel">Complete SPF, publish a valid DKIM key, and verify legitimate sender alignment before moving to <code>p=reject</code>.</p>
                @else
                    <p>Use the generated configuration and publishing steps in the matching technical check.</p>
                    <div class="mx-recommendation-buttons">
                        @if(!empty($rec['action']) && !empty($rec['technical_target']))
                            <a href="#{{ $rec['technical_target'] }}" class="mx-btn mx-btn-primary">{{ $rec['action'] }}</a>
                        @endif
                        <a href="#{{ $rec['technical_target'] ?? 'technical-checks' }}" class="mx-btn mx-btn-secondary">View evidence</a>
                    </div>
                @endif
            </section>

            <section>
                <h4>Verification</h4>
                <p>Publish the change, then select Re-scan domain in the technical check.</p>
            </section>
        </div>
    </div>
</article>
