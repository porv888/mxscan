@props([
    'title' => 'No scan history yet',
    'description' => 'Run the first scan to begin tracking score changes.',
])

<div class="dashboard-chart-empty" role="status">
    <i data-lucide="chart-no-axes-combined" aria-hidden="true"></i>
    <h3>{{ $title }}</h3>
    <p>{{ $description }}</p>
</div>
