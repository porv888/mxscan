@extends('layouts.app')

@section('title', 'Pricing')

@section('content')
<div class="max-w-6xl mx-auto py-10">
    <h1 class="text-3xl font-bold mb-6">Choose your plan</h1>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        @foreach($plans as $plan)
            <div class="border rounded-xl p-6 bg-white shadow">
                <h2 class="text-xl font-semibold">{{ $plan['name'] }}</h2>
                <div class="text-sm text-gray-600 mt-1">Limit: {{ $plan['limit'] }} domains</div>

                <div class="mt-6 space-y-2">
                    @if($plan['key'] === 'freemium')
                        <a href="{{ route('dashboard.domains') }}" class="mx-btn mx-btn-secondary mx-btn-block">
                            Continue free
                        </a>
                    @else
                        @if($plan['has_monthly'])
                            <form method="POST" action="{{ route('billing.checkout', ['plan' => $plan['key'], 'interval' => 'monthly']) }}">
                                @csrf
                                <button class="mx-btn mx-btn-primary mx-btn-block">Choose Monthly</button>
                            </form>
                        @endif

                        @if($enableYearly && $plan['has_yearly'])
                            <form method="POST" action="{{ route('billing.checkout', ['plan' => $plan['key'], 'interval' => 'yearly']) }}">
                                @csrf
                                <button class="mx-btn mx-btn-primary mx-btn-block">Choose Yearly</button>
                            </form>
                        @endif
                    @endif
                </div>
            </div>
        @endforeach
    </div>

    <div class="mt-8">
        <a href="{{ route('billing.portal') }}" class="underline text-blue-600">Manage billing in customer portal</a>
    </div>
</div>
@endsection
