@php
    $showChart = $presenter->shouldShowChart();
    $empty = $presenter->historyEmptyState(
        $scan->finished_at?->timezone(auth()->user()->timezone ?? 'UTC')->format('j F Y')
            ?? $scan->created_at->format('j F Y')
    );
@endphp

<section class="rounded-2xl border border-gray-200/80 bg-white p-5 shadow-sm lg:p-6">
    <h2 class="text-xl font-semibold text-gray-900">Score history</h2>

    @if($showChart)
        <div class="mt-4 h-[220px] max-h-[220px] min-w-0 overflow-hidden">
            <canvas id="reportScoreTrend" class="max-h-[220px] max-w-full"></canvas>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('reportScoreTrend');
            if (!ctx) return;
            const data = @json($scoreTrend);
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Score',
                        data: data.scores,
                        borderColor: '#2563eb',
                        backgroundColor: 'rgba(37, 99, 235, 0.08)',
                        fill: true,
                        tension: 0.3,
                        spanGaps: true,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { min: 0, max: 100, ticks: { stepSize: 20 } } },
                    plugins: { legend: { display: false } }
                }
            });
        });
        </script>
    @else
        <div class="mt-4 max-h-40 rounded-xl bg-gray-50 p-4 ring-1 ring-gray-200">
            <dl class="grid gap-2 sm:grid-cols-2">
                <div>
                    <dt class="text-[13px] text-gray-500">Current score</dt>
                    <dd class="text-2xl font-semibold text-gray-900">{{ $empty['score'] ?? '—' }}</dd>
                </div>
                <div>
                    <dt class="text-[13px] text-gray-500">Scan date</dt>
                    <dd class="text-sm font-medium text-gray-900">{{ $empty['date'] }}</dd>
                </div>
            </dl>
            <p class="mt-3 text-sm text-gray-600">{{ $empty['message'] }}</p>
            <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="mt-3">
                @csrf
                <input type="hidden" name="mode" value="full">
                <button type="submit" class="mx-btn mx-btn-secondary mx-btn-sm">Scan again</button>
            </form>
        </div>
    @endif
</section>
