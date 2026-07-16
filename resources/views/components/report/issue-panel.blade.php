@props([
    'title',
    'severity' => 'warning',
    'impact' => null,
    'earned' => null,
    'possible' => null,
    'lostPoints' => null,
    'optional' => false,
])

<section {{ $attributes->merge(['class' => 'report-issue-panel mx-tech-issue-panel']) }} aria-label="Issue">
    <div class="mx-tech-panel-label">Issue</div>
    <div class="mx-tech-issue-heading">
        <div>
            <h4>{{ $title }}</h4>
            @if($impact)
                <p>{{ $impact }}</p>
            @endif
        </div>
        <div class="mx-tech-issue-metrics">
            <span>{{ $optional ? 'Optional' : ucfirst($severity) . ' severity' }}</span>
            @if(!$optional && $earned !== null && $possible !== null)
                <span>{{ $earned }}/{{ $possible }} points</span>
            @endif
            @if(!$optional && $lostPoints)
                <strong>-{{ $lostPoints }} points</strong>
            @endif
        </div>
    </div>
</section>
