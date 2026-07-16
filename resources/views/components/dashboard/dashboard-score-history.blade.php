@props(['history', 'latestScore' => null, 'latestScanId' => null])

<section
    class="dashboard-score-history"
    aria-labelledby="dashboard-score-history-title"
    data-latest-score="{{ $latestScore }}"
    data-latest-scan-id="{{ $latestScanId }}"
>
    <div class="dashboard-section-heading">
        <div>
            <h2 id="dashboard-score-history-title">Security score history</h2>
            @if(($history['count'] ?? 0) > 0)
                <p>
                    {{ $history['count'] }} {{ Str::plural('scan', $history['count']) }} available
                    @if($history['count'] < 5)
                        · More history will appear as scheduled scans run.
                    @endif
                </p>
            @endif
        </div>
    </div>

    @if(($history['count'] ?? 0) === 0)
        <x-dashboard.empty-chart-state />
    @else
        <p class="sr-only">
            The latest score is {{ $latestScore }} out of 100.
            {{ $history['count'] }} scan {{ Str::plural('point', $history['count']) }} are shown.
        </p>
        <div class="dashboard-chart-wrap {{ $history['count'] < 5 ? 'dashboard-chart-wrap--sparse' : '' }}">
            <canvas
                id="dashboardScoreHistory"
                role="img"
                aria-label="Security score history for the latest domain"
            ></canvas>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
        document.addEventListener('DOMContentLoaded', function () {
            const canvas = document.getElementById('dashboardScoreHistory');
            if (!canvas || typeof Chart === 'undefined') return;
            const history = @json($history);
            const sparse = history.count < 5;
            new Chart(canvas, {
                type: 'line',
                data: {
                    labels: history.labels,
                    datasets: [{
                        label: 'Security score',
                        data: history.scores,
                        borderColor: '#2563eb',
                        backgroundColor: 'rgba(37, 99, 235, 0.08)',
                        borderWidth: 2,
                        pointRadius: sparse ? 5 : 3,
                        pointHoverRadius: 6,
                        fill: !sparse,
                        tension: sparse ? 0 : 0.25
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { intersect: false, mode: 'nearest' },
                    scales: {
                        x: {
                            grid: { display: !sparse },
                            ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 6 }
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { display: !sparse },
                            ticks: { stepSize: sparse ? 25 : 20 }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: items => history.labels[items[0].dataIndex],
                                label: item => `Score: ${item.raw}/100`,
                                afterLabel: item => `Status: ${history.statuses[item.dataIndex]}`
                            }
                        }
                    }
                }
            });
        });
        </script>
    @endif
</section>
