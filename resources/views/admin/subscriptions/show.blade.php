@extends('admin.layouts.app')

@section('page-title', 'Subscription #'.$subscription->id)

@section('content')
<div class="mb-6">
  <h1 class="text-2xl font-semibold">Subscription #{{ $subscription->id }}</h1>
  <div class="text-sm text-gray-600 mt-1">
    User: <strong>{{ $subscription->user->name }}</strong> ({{ $subscription->user->email }})
  </div>
</div>

<div class="grid md:grid-cols-3 gap-6">
  {{-- Left: details & edit --}}
  <div class="md:col-span-2">
    <form method="post" action="{{ route('admin.subscriptions.update',$subscription) }}" class="bg-white shadow overflow-hidden sm:rounded-lg p-6 space-y-4">
      @csrf @method('PUT')
      <div class="grid md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700">Plan</label>
          <select class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="plan_id">
            <option value="">— Keep Current —</option>
            @foreach($plans as $p)
              <option value="{{ $p->id }}" @selected(optional($subscription->plan)->id === $p->id)>
                {{ $p->name }} ({{ $p->domain_limit }} domains) @if($p->price>0) — €{{ number_format($p->price,2) }}/mo @endif
              </option>
            @endforeach
          </select>
          @error('plan_id') <div class="text-sm text-red-600">{{ $message }}</div> @enderror
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Status</label>
          <select class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="status">
            @foreach(['active','trialing','trial','past_due','canceled'] as $st)
              <option value="{{ $st }}" @selected($subscription->status === $st)>{{ ucfirst(str_replace('_',' ',$st)) }}</option>
            @endforeach
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Renews At</label>
          <input type="date" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="renews_at" value="{{ optional($subscription->renews_at)?->toDateString() }}">
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700">Started At</label>
          <input type="text" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm bg-gray-50" value="{{ optional($subscription->started_at)?->toDateTimeString() }}" disabled>
        </div>
      </div>

      <div>
        <label class="block text-sm font-medium text-gray-700">Internal Notes</label>
        <textarea name="notes" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 min-h-[100px]" placeholder="Visible to admins only">{{ old('notes',$subscription->notes) }}</textarea>
      </div>

      <div class="flex gap-3">
        <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Save Changes</button>
        <a href="{{ route('admin.subscriptions.index') }}" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">Back</a>
      </div>
    </form>

    {{-- Danger actions --}}
    <div class="bg-white shadow overflow-hidden sm:rounded-lg p-6 mt-6">
      <div class="flex items-center justify-between">
        <div>
          <div class="font-medium">Status: 
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $subscription->status==='active'?'bg-green-100 text-green-800':($subscription->status==='canceled'?'bg-red-100 text-red-800':'bg-yellow-100 text-yellow-800') }}">
              {{ ucfirst(str_replace('_',' ',$subscription->status)) }}
            </span>
          </div>
          <div class="text-sm text-gray-500 mt-1">Usage: {{ $used }} / {{ $limit }} domains</div>
        </div>

        <div class="flex gap-2">
          @if($subscription->status !== 'canceled')
            <form method="post" action="{{ route('admin.subscriptions.cancel',$subscription) }}">
              @csrf
              <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700" onclick="return confirm('Cancel this subscription?')">Cancel</button>
            </form>
          @else
            <form method="post" action="{{ route('admin.subscriptions.resume',$subscription) }}">
              @csrf
              <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700">Resume</button>
            </form>
          @endif
        </div>
      </div>
    </div>
  </div>

  {{-- Right: quick info --}}
  <div>
    <div class="bg-white shadow overflow-hidden sm:rounded-lg p-6">
      <div class="text-gray-500 text-sm">Plan</div>
      <div class="text-lg font-medium">{{ $subscription->plan?->name ?? '—' }}</div>
      <div class="text-sm text-gray-500 mt-1">
        Price: €{{ number_format($subscription->plan->price ?? 0, 2) }}
      </div>
      <div class="text-sm text-gray-500 mt-1">
        Domains: {{ $limit }}
      </div>
      <div class="text-sm text-gray-500 mt-1">
        Started: {{ optional($subscription->started_at)?->toDateString() ?? '—' }}
      </div>
      <div class="text-sm text-gray-500 mt-1">
        Renews: {{ optional($subscription->renews_at)?->toDateString() ?? '—' }}
      </div>
    </div>
  </div>
</div>
@endsection
