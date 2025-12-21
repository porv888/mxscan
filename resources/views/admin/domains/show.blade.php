@extends('admin.layouts.app')

@section('page-title', 'Domain · '.$domain->domain)

@section('content')
<div class="mb-6">
  <a href="{{ route('admin.domains.index') }}" class="text-sm text-gray-500 hover:underline">← Back to domains</a>
</div>

<div class="grid gap-6 md:grid-cols-3">
  <div class="bg-white shadow overflow-hidden sm:rounded-lg md:col-span-2">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Overview</h3>
    </div>
    <div class="border-t border-gray-200 px-4 py-5 sm:p-0">
      <dl class="sm:divide-y sm:divide-gray-200">
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Domain</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $domain->domain }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Owner</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ optional($domain->user)->email }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Score</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $domain->score_last ?? '—' }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Blacklist</dt>
          <dd class="mt-1 sm:mt-0 sm:col-span-2">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $domain->blacklist_status==='listed'?'bg-red-100 text-red-800':($domain->blacklist_status==='clean'?'bg-green-100 text-green-800':'bg-gray-100 text-gray-800') }}">
              {{ $domain->blacklist_status ?: 'not-checked' }}
            </span>
          </dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Last Scan</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $domain->last_scanned_at? $domain->last_scanned_at->diffForHumans() : 'Never' }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Status</dt>
          <dd class="mt-1 sm:mt-0 sm:col-span-2">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $domain->status==='active'?'bg-green-100 text-green-800':($domain->status==='pending'?'bg-yellow-100 text-yellow-800':'bg-gray-100 text-gray-800') }}">{{ ucfirst($domain->status) }}</span>
          </dd>
        </div>
      </dl>
    </div>

    <form action="{{ route('admin.domains.update',$domain) }}" method="post" class="px-4 py-5 sm:px-6 border-t border-gray-200">
      @csrf @method('PATCH')
      <div class="grid md:grid-cols-3 gap-3">
        <input class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="provider_guess" value="{{ old('provider_guess',$domain->provider_guess) }}" placeholder="Provider">
        <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="status">
          @foreach(['active','pending','paused'] as $s)
          <option value="{{ $s }}" @selected($domain->status===$s)>{{ ucfirst($s) }}</option>
          @endforeach
        </select>
        <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Save</button>
      </div>
    </form>
  </div>

  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Actions</h3>
    </div>
    <div class="border-t border-gray-200 px-4 py-5 sm:p-6 space-y-3">
      <form action="{{ route('admin.domains.scan',$domain) }}" method="post">@csrf
        <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700">
          <i data-lucide="search" class="w-4 h-4 mr-2"></i>
          Run Scan
        </button>
      </form>
      <form action="{{ route('admin.domains.blacklist',$domain) }}" method="post">@csrf
        <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
          <i data-lucide="shield-alert" class="w-4 h-4 mr-2"></i>
          Run Blacklist
        </button>
      </form>
      <form action="{{ route('admin.domains.transfer',$domain) }}" method="post" class="space-y-2">@csrf
        <label class="block text-sm text-gray-600">Transfer Ownership (User ID)</label>
        <input class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="new_user_id" placeholder="New owner user_id">
        <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
          <i data-lucide="user-check" class="w-4 h-4 mr-2"></i>
          Transfer
        </button>
      </form>
      <form action="{{ route('admin.domains.destroy',$domain) }}" method="post" onsubmit="return confirm('Delete this domain?')">
        @csrf @method('DELETE')
        <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
          <i data-lucide="trash-2" class="w-4 h-4 mr-2"></i>
          Delete Domain
        </button>
      </form>
    </div>
  </div>
</div>

@if(isset($recentScans) && $recentScans->count())
<div class="bg-white shadow overflow-hidden sm:rounded-lg mt-6">
  <div class="px-4 py-5 sm:px-6">
    <h3 class="text-lg leading-6 font-medium text-gray-900">Recent Scans</h3>
  </div>
  <div class="border-t border-gray-200">
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
        @foreach($recentScans as $s)
          <tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ $s->id }}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ ucfirst($s->status) }}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $s->score ?? '—' }}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $s->created_at->format('Y-m-d H:i') }}</td>
          </tr>
        @endforeach
        </tbody>
      </table>
    </div>
  </div>
</div>
@endif
@endsection
