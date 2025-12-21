@extends('admin.layouts.app')

@section('page-title', 'Subscriptions')

@section('content')
<div class="mb-6">
  <h1 class="text-2xl font-semibold">Subscriptions</h1>
</div>

{{-- KPI cards --}}
<div class="grid md:grid-cols-4 gap-4 mb-6">
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:p-6">
      <div class="text-gray-500 text-sm">Active</div>
      <div class="text-2xl font-semibold">{{ $kpi['active'] }}</div>
    </div>
  </div>
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:p-6">
      <div class="text-gray-500 text-sm">Trialing</div>
      <div class="text-2xl font-semibold">{{ $kpi['trialing'] }}</div>
    </div>
  </div>
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:p-6">
      <div class="text-gray-500 text-sm">Canceled</div>
      <div class="text-2xl font-semibold">{{ $kpi['canceled'] }}</div>
    </div>
  </div>
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:p-6">
      <div class="text-gray-500 text-sm">MRR (Active)</div>
      <div class="text-2xl font-semibold">€{{ number_format($kpi['mrr'],2) }}</div>
    </div>
  </div>
</div>

{{-- Filters --}}
<form method="get" class="bg-white shadow overflow-hidden sm:rounded-lg p-6 mb-6 grid md:grid-cols-6 gap-3">
  <input type="text" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 md:col-span-2" name="q" value="{{ $search }}" placeholder="Search user name/email">
  <select name="status" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500">
    <option value="">All Status</option>
    @foreach(['active','trialing','trial','past_due','canceled'] as $st)
      <option value="{{ $st }}" @selected($status===$st)>{{ ucfirst(str_replace('_',' ',$st)) }}</option>
    @endforeach
  </select>
  <select name="plan_id" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500">
    <option value="">All Plans</option>
    @foreach($plans as $p)
      <option value="{{ $p->id }}" @selected($planId==$p->id)>{{ $p->name }}</option>
    @endforeach
  </select>
  <input type="date" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="from" value="{{ $from }}">
  <input type="date" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="to" value="{{ $to }}">
  <div class="flex gap-2 md:col-span-6 mt-1">
    <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Filter</button>
    <a href="{{ route('admin.subscriptions.export', request()->query()) }}" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">Export CSV</a>
  </div>
</form>

{{-- Table --}}
<div class="bg-white shadow overflow-hidden sm:rounded-lg overflow-x-auto">
  <table class="w-full min-w-[900px]">
    <thead class="bg-gray-50">
      <tr class="text-left text-sm text-gray-600">
        <th class="px-6 py-3">User</th>
        <th class="px-6 py-3">Plan</th>
        <th class="px-6 py-3">Status</th>
        <th class="px-6 py-3">Price</th>
        <th class="px-6 py-3">Usage</th>
        <th class="px-6 py-3">Started</th>
        <th class="px-6 py-3">Renews</th>
        <th class="px-6 py-3"></th>
      </tr>
    </thead>
    <tbody class="bg-white divide-y divide-gray-200">
    @foreach($subs as $s)
      @php
        $used  = $s->user?->domains()->count() ?? 0;
        $limit = $s->plan?->domain_limit ?? 1;
      @endphp
      <tr>
        <td class="px-6 py-4">
          <div class="font-medium">{{ $s->user?->name ?? '—' }}</div>
          <div class="text-xs text-gray-500">{{ $s->user?->email }}</div>
        </td>
        <td class="px-6 py-4">{{ $s->plan?->name ?? '—' }}</td>
        <td class="px-6 py-4">
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $s->status === 'active' ? 'bg-green-100 text-green-800' : ($s->status==='canceled' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800') }}">
            {{ ucfirst(str_replace('_',' ', $s->status)) }}
          </span>
        </td>
        <td class="px-6 py-4">€{{ number_format($s->plan->price ?? 0, 2) }}</td>
        <td class="px-6 py-4 text-sm">{{ $used }} / {{ $limit }}</td>
        <td class="px-6 py-4 text-sm">{{ optional($s->started_at)?->toDateString() ?? '—' }}</td>
        <td class="px-6 py-4 text-sm">{{ optional($s->renews_at)?->toDateString() ?? '—' }}</td>
        <td class="px-6 py-4 text-right">
          <a href="{{ route('admin.subscriptions.show',$s) }}" class="inline-flex items-center px-3 py-1 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">View</a>
        </td>
      </tr>
    @endforeach
    </tbody>
  </table>
</div>

<div class="mt-4">
  {{ $subs->links() }}
</div>
@endsection