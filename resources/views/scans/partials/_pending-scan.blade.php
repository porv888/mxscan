{{-- Pending / failed scan progress --}}
@php
    $domainName = $domain->domain ?? 'your domain';
    $initialStage = match ($scan->status) {
        'queued' => 'queued',
        'failed' => 'failed',
        'finished' => 'completed',
        default => ((int) ($scan->progress_pct ?? 0) >= 90 ? 'preparing_report' : 'scanning'),
    };
@endphp
<div class="max-w-2xl mx-auto"
     x-data="scanProgress({
        statusUrl: @js(route('scans.status', $scan)),
        retryUrl: @js(route('domains.scan.now', $domain)),
        initialStatus: @js($scan->status),
        initialStage: @js($initialStage),
        initialMessage: @js($scan->status === 'failed'
            ? (data_get($scan->result_json, 'user_error') ?? 'The scan could not be completed. Please try again.')
            : 'MXScan is checking your DNS authentication, blacklist status, certificate, and email-security configuration.')
     })"
     x-init="start()">
    <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6 sm:p-8">
        <h1 id="scan-status-heading" tabindex="-1" class="text-2xl font-semibold text-gray-900 dark:text-gray-100 focus:outline-none">
            <span x-text="status === 'failed' ? ('Scan failed for ' + @js($domainName)) : ('Scanning ' + @js($domainName))">
                @if($scan->status === 'failed')
                    Scan failed for {{ $domainName }}
                @else
                    Scanning {{ $domainName }}
                @endif
            </span>
        </h1>
        <p class="mt-2 text-sm text-gray-600 dark:text-gray-400" x-show="status !== 'failed'">
            MXScan is checking your DNS authentication, blacklist status, certificate, and email-security configuration.
        </p>
        <p class="mt-2 text-sm text-red-600 dark:text-red-400" x-show="status === 'failed'" x-cloak x-text="message" role="alert"></p>

        <ol class="mt-8 space-y-3" aria-label="Scan progress stages">
            <template x-for="step in stages" :key="step.id">
                <li class="flex items-center gap-3 text-sm"
                    :class="stepState(step.id) === 'done' ? 'text-green-700' : (stepState(step.id) === 'current' ? 'text-blue-700 font-medium' : 'text-gray-400')">
                    <span class="flex h-6 w-6 items-center justify-center rounded-full border text-xs"
                          :class="stepState(step.id) === 'done' ? 'border-green-500 bg-green-50' : (stepState(step.id) === 'current' ? 'border-blue-500 bg-blue-50' : 'border-gray-200')">
                        <span x-text="stepState(step.id) === 'done' ? '✓' : step.index"></span>
                    </span>
                    <span x-text="step.label"></span>
                </li>
            </template>
        </ol>

        <p class="mt-6 text-sm text-gray-500" x-show="status !== 'failed'" x-text="message"></p>
        {{-- Announce only on stage changes to avoid excessive live-region updates while polling --}}
        <div class="sr-only" aria-live="polite" x-text="announcement"></div>

        <div class="mt-6" x-show="status === 'failed'" x-cloak>
            <form method="POST" :action="retryUrl">
                @csrf
                <input type="hidden" name="mode" value="full">
                <button type="submit"
                        class="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    Retry scan
                </button>
            </form>
        </div>
    </div>
</div>

<script>
function scanProgress(config) {
    return {
        statusUrl: config.statusUrl,
        retryUrl: config.retryUrl,
        status: config.initialStatus,
        stage: config.initialStage,
        message: config.initialMessage,
        announcement: '',
        lastAnnouncedStage: null,
        timer: null,
        stages: [
            { id: 'queued', label: 'Queued', index: 1 },
            { id: 'scanning', label: 'Scanning', index: 2 },
            { id: 'preparing_report', label: 'Preparing report', index: 3 },
            { id: 'completed', label: 'Completed', index: 4 },
            { id: 'failed', label: 'Failed', index: 5 },
        ],
        order: ['queued', 'scanning', 'preparing_report', 'completed'],
        start() {
            this.$nextTick(() => {
                const heading = document.getElementById('scan-status-heading');
                if (heading) heading.focus();
            });
            this.announceStage(this.stage, this.message);
            if (this.status === 'finished' || this.status === 'failed') return;
            this.poll();
            this.timer = setInterval(() => this.poll(), 3000);
        },
        announceStage(stage, message) {
            if (stage === this.lastAnnouncedStage) return;
            this.lastAnnouncedStage = stage;
            const labels = {
                queued: 'Queued',
                scanning: 'Scanning',
                preparing_report: 'Preparing report',
                completed: 'Completed',
                failed: 'Failed',
            };
            this.announcement = (labels[stage] || stage) + (message ? '. ' + message : '');
        },
        stepState(id) {
            if (this.status === 'failed' || this.stage === 'failed') {
                if (id === 'failed') return 'current';
                if (id === 'completed') return 'todo';
                if (id === 'queued' || id === 'scanning') return 'done';
                return 'todo';
            }
            if (id === 'failed') return 'todo';
            const currentIdx = this.order.indexOf(this.stage);
            const stepIdx = this.order.indexOf(id);
            if (stepIdx < 0) return 'todo';
            if (stepIdx < currentIdx) return 'done';
            if (stepIdx === currentIdx) return 'current';
            return 'todo';
        },
        async poll() {
            try {
                const res = await fetch(this.statusUrl, {
                    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                });
                if (!res.ok) return;
                const data = await res.json();
                if (data.message) this.message = data.message;
                this.status = data.status;
                this.stage = data.stage;
                this.announceStage(data.stage, data.message);
                if (data.status === 'finished') {
                    clearInterval(this.timer);
                    window.location.reload();
                }
                if (data.status === 'failed') {
                    clearInterval(this.timer);
                }
            } catch (e) {}
        }
    }
}
</script>
