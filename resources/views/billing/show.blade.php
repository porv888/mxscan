@extends('layouts.app')

@section('title', 'Billing & Subscription')

@section('content')
<div class="max-w-4xl mx-auto px-4 py-8">
    @if (session('status'))
        <div class="mb-4 rounded bg-emerald-50 text-emerald-700 px-4 py-3">{{ session('status') }}</div>
    @endif
    @if (session('error'))
        <div class="mb-4 rounded bg-red-50 text-red-700 px-4 py-3">{{ session('error') }}</div>
    @endif

    <h1 class="text-2xl font-semibold mb-6">Subscription</h1>

    {{-- Current status (internal subscription source of truth) --}}
    <div class="rounded border p-4 mb-8">
        @if($planKey !== 'freemium')
            <div class="text-slate-700">
                <div><strong>Plan:</strong>
                    {{ $appPlan->name ?? 'Unknown' }}
                    @if(!empty($appPlan?->domain_limit))
                        ({{ $appPlan->domain_limit }} domains)
                    @endif
                </div>
                <div><strong>Status:</strong> {{ $appSubscription->status ?? 'active' }}</div>
                <div><strong>Renews:</strong> {{ optional($appSubscription?->renews_at)?->toDayDateTimeString() ?? '—' }}</div>
            </div>
        @else
            <div class="text-slate-700">You are on the <strong>Freemium</strong> plan ({{ $freemiumLimit ?? 3 }} domains).</div>
        @endif
    </div>

    {{-- Plan cards --}}
    <div class="grid md:grid-cols-2 gap-6">
        {{-- Premium --}}
        <div class="rounded border p-6 bg-white">
            <div class="text-sm uppercase text-slate-500">Premium</div>
            <div class="text-3xl font-bold mt-1">{{ $displayPremium ?? '€19' }}<span class="text-base font-medium text-slate-500">/mo</span></div>
            <ul class="mt-3 text-sm text-slate-600 space-y-1">
                <li>Up to {{ $premiumLimit ?? 9 }} domains</li>
                <li>Scheduled scans</li>
                <li>Blacklist monitoring</li>
                <li>DMARC visibility (30 days)</li>
            </ul>

            @if($onFreemium)
                {{-- Start new subscription via Checkout --}}
                <form method="POST" action="{{ route('billing.checkout') }}" class="mt-4">
                    @csrf
                    <input type="hidden" name="price" value="{{ $pricePremium }}">
                    <button class="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700">Start Premium</button>
                </form>
            @elseif($isPremium)
                <div class="mt-4 text-sm text-emerald-700">You’re on Premium.</div>
            @else
                {{-- Swap to Premium --}}
                <form method="POST" action="{{ route('billing.swap') }}" class="mt-4">
                    @csrf
                    <input type="hidden" name="price" value="{{ $pricePremium }}">
                    <button class="px-4 py-2 rounded border hover:bg-white">Switch to Premium</button>
                </form>
            @endif
        </div>

        {{-- Ultra --}}
        <div class="rounded border p-6 bg-white relative">
            <span class="absolute -top-3 right-4 text-xs bg-blue-600 text-white px-2 py-0.5 rounded">Most popular</span>
            <div class="text-sm uppercase text-slate-500">Ultra</div>
            <div class="text-3xl font-bold mt-1">{{ $displayUltra ?? '€49' }}<span class="text-base font-medium text-slate-500">/mo</span></div>
            <ul class="mt-3 text-sm text-slate-600 space-y-1">
                <li>Up to {{ $ultraLimit ?? 19 }} domains</li>
                <li>Everything in Premium</li>
                <li>DMARC visibility (90 days)</li>
                <li>Priority support</li>
            </ul>

            @if($onFreemium)
                {{-- Start new subscription via Checkout --}}
                <form method="POST" action="{{ route('billing.checkout') }}" class="mt-4">
                    @csrf
                    <input type="hidden" name="price" value="{{ $priceUltra }}">
                    <button class="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700">Start Ultra</button>
                </form>
            @elseif($isUltra)
                <div class="mt-4 text-sm text-emerald-700">You’re on Ultra.</div>
            @else
                {{-- Swap to Ultra --}}
                <form method="POST" action="{{ route('billing.swap') }}" class="mt-4">
                    @csrf
                    <input type="hidden" name="price" value="{{ $priceUltra }}">
                    <button class="px-4 py-2 rounded border hover:bg-white">Switch to Ultra</button>
                </form>
            @endif
        </div>
    </div>

    {{-- Billing portal --}}
    <div class="mt-8 rounded border p-6 bg-white">
        <div class="flex items-center justify-between">
            <div>
                <div class="font-medium">Manage billing</div>
                <div class="text-sm text-slate-600">Update card, view invoices, cancel or resume</div>
            </div>
            <form method="POST" action="{{ route('billing.portal') }}">
                @csrf
                <button class="px-4 py-2 rounded border hover:bg-white">Open Billing Portal</button>
            </form>
        </div>
    </div>
</div>
@endsection
