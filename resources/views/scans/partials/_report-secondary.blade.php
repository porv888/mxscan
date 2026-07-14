@php
    $recentScans = $domain->scans()->where('status', 'finished')->latest('finished_at')->limit(5)->get();
@endphp

<section class="space-y-4">
    @if($incidents->count() > 0)
        <div class="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
                <p class="text-sm font-medium text-gray-900">Active incidents ({{ $incidents->count() }})</p>
                <a href="#what-to-fix" class="text-sm font-medium text-blue-700 hover:underline">Resolve</a>
            </div>
            <ul class="mt-2 space-y-1">
                @foreach($incidents->take(3) as $incident)
                    <li class="text-sm text-gray-700">{{ $incident->message }}</li>
                @endforeach
            </ul>
        </div>
    @endif

    <div class="grid gap-4 lg:grid-cols-2">
        <div class="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
            <h3 class="text-base font-semibold text-gray-900">Renewal reminders</h3>
            <dl class="mt-3 space-y-2 text-sm">
                <div class="flex justify-between gap-4">
                    <dt class="text-gray-600">Domain</dt>
                    <dd class="font-medium text-gray-900">{{ $domainDays !== null ? $domainDays . ' days' : 'unknown' }}</dd>
                </div>
                <div class="flex justify-between gap-4">
                    <dt class="text-gray-600">SSL</dt>
                    <dd class="font-medium text-gray-900">{{ $sslDays !== null ? $sslDays . ' days' : 'unknown' }}</dd>
                </div>
            </dl>
            <a href="{{ route('domains.hub.settings', $domain) }}#renewals" class="mt-3 inline-block text-sm font-medium text-blue-700 hover:underline">Edit dates</a>
        </div>

        <div class="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
            <h3 class="text-base font-semibold text-gray-900">Monitoring schedule</h3>
            <p class="mt-2 text-sm text-gray-600">Current cadence: <span class="font-medium text-gray-900">{{ ucfirst($cadence) }}</span></p>
            <a href="{{ route('automations.index') }}" class="mt-3 inline-block text-sm font-medium text-blue-700 hover:underline">Manage schedule</a>
        </div>
    </div>

    <div class="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h3 class="text-base font-semibold text-gray-900">Recent scans</h3>
        @if($recentScans->isEmpty())
            <p class="mt-2 text-sm text-gray-600">No completed scans yet.</p>
        @else
            <ul class="mt-3 divide-y divide-gray-100">
                @foreach($recentScans as $recent)
                    <li class="flex items-center justify-between gap-3 py-2 text-sm">
                        <span class="text-gray-600">{{ $recent->finished_at?->format('j M Y H:i') ?? $recent->created_at->format('j M Y H:i') }}</span>
                        <span class="font-medium text-gray-900">{{ $recent->score ?? '—' }}/100</span>
                        @if($recent->id === $scan->id)
                            <span class="text-xs text-gray-500">Current</span>
                        @else
                            <a href="{{ route('scans.show', $recent) }}" class="text-sm font-medium text-blue-700 hover:underline">View</a>
                        @endif
                    </li>
                @endforeach
            </ul>
        @endif
    </div>

    <div class="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h3 class="text-base font-semibold text-gray-900">Quick actions</h3>
        <form method="POST" action="{{ route('domains.scan.now', $domain) }}" class="mt-3 space-y-3" x-data="{ dns: true, spf: false, blacklist: true }">
            @csrf
            <input type="hidden" name="mode" value="full">
            <div class="flex flex-wrap gap-2">
                <label class="inline-flex cursor-pointer items-center rounded-full px-3 py-1.5 text-xs font-medium transition-colors" :class="dns ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'">
                    <input type="checkbox" x-model="dns" class="sr-only"><span>DNS</span>
                </label>
                <label class="inline-flex cursor-pointer items-center rounded-full px-3 py-1.5 text-xs font-medium transition-colors" :class="spf ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'">
                    <input type="checkbox" x-model="spf" class="sr-only"><span>SPF</span>
                </label>
                @if(auth()->user()->can('blacklist', $domain))
                <label class="inline-flex cursor-pointer items-center rounded-full px-3 py-1.5 text-xs font-medium transition-colors" :class="blacklist ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'">
                    <input type="checkbox" x-model="blacklist" class="sr-only"><span>Blacklist</span>
                </label>
                @endif
            </div>
            <button type="submit" class="mx-btn mx-btn-secondary mx-btn-sm">Scan selected checks</button>
        </form>
    </div>

    @if($enabled['delivery'] && $deliveries->count() > 0)
        @include('scans.partials._delivery-section', ['deliveries' => $deliveries, 'domain' => $domain])
    @endif
</section>
