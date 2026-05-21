@if(!empty($scoreDeductions))
<div class="mt-4 rounded-lg border border-amber-200 bg-amber-50/50 dark:border-amber-800 dark:bg-amber-900/10 p-3">
    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100">Score breakdown</h4>
    <p class="text-xs text-gray-600 dark:text-gray-400 mt-0.5">Points not earned toward 100</p>
    <ul class="mt-3 space-y-2">
        @foreach($scoreDeductions as $row)
        @php
            $lost = $row['possible'] - $row['earned'];
            $target = match($row['key'] ?? '') {
                'spf', 'dmarc', 'tlsrpt', 'mtasts', 'bimi', 'mx', 'dkim' => '#fix-pack',
                default => '#dns-security',
            };
        @endphp
        <li>
            <a href="{{ $target }}" class="flex items-start justify-between gap-2 text-sm rounded px-1 py-0.5 hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors">
            <span class="text-gray-800 dark:text-gray-200">
                {{ $row['label'] }}
                @if($row['status'] === 'missing')
                    <span class="text-gray-500">— missing</span>
                @elseif($row['status'] === 'partial')
                    <span class="text-gray-500">— partial</span>
                @endif
            </span>
            <span class="font-medium text-amber-700 dark:text-amber-400 shrink-0">−{{ $lost }}</span>
            </a>
        </li>
        @endforeach
    </ul>
    @if(collect($scoreBreakdown)->sum('earned') < 100)
    <p class="text-xs text-gray-500 mt-3">
        Earned {{ collect($scoreBreakdown)->sum('earned') }} of 100 possible DNS points (capped at 100).
    </p>
    @endif
</div>
@endif
