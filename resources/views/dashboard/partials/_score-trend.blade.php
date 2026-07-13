<div class="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
    <h3 class="text-sm font-semibold text-gray-900">Email Security Score (30 days)</h3>
    <p class="text-xs text-gray-500 mt-0.5">Authentication and transport-security configuration</p>
    <p class="text-xs text-gray-500 mt-0.5">Average score across your domains per day</p>
    <div class="mt-4 h-48 min-w-0 overflow-hidden">
        <canvas id="{{ $chartId }}" class="max-w-full"></canvas>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    const ctx = document.getElementById(@json($chartId));
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
            scales: {
                y: { min: 0, max: 100, ticks: { stepSize: 20 } }
            },
            plugins: { legend: { display: false } }
        }
    });
    if (typeof lucide !== 'undefined') lucide.createIcons();
});
</script>
