@extends('admin.layouts.app')

@section('page-title', 'Domains')

@section('content')
<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-semibold">Domains</h1>
  <a href="{{ route('admin.domains.export', request()->query()) }}" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
    <i data-lucide="download" class="w-4 h-4 mr-2"></i>
    Export CSV
  </a>
</div>

<form method="get" class="grid md:grid-cols-5 gap-3 mb-4">
  <input class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" type="text" name="keyword" value="{{ request('keyword') }}" placeholder="Search domain">
  <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="status">
    <option value="">All Statuses</option>
    @foreach(['active','pending','paused'] as $s)
      <option value="{{ $s }}" @selected(request('status')===$s)>{{ ucfirst($s) }}</option>
    @endforeach
  </select>
  <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="blacklist">
    <option value="">Blacklist: Any</option>
    <option value="clean" @selected(request('blacklist')==='clean')>Clean</option>
    <option value="listed" @selected(request('blacklist')==='listed')>Listed</option>
    <option value="unchecked" @selected(request('blacklist')==='unchecked')>Not Checked</option>
  </select>
  <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="sort">
    @foreach(['last_scanned_at'=>'Last Scan','score_last'=>'Score','domain'=>'Domain'] as $k=>$label)
      <option value="{{ $k }}" @selected(request('sort',$k)===$k)>{{ $label }}</option>
    @endforeach
  </select>
  <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="dir">
    <option value="desc" @selected(request('dir')==='desc')>Desc</option>
    <option value="asc"  @selected(request('dir')==='asc')>Asc</option>
  </select>
  <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 md:col-span-5">Apply</button>
</form>

<div class="bg-white shadow overflow-hidden sm:rounded-md">
  <div class="overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Blacklist</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
          <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
        </tr>
      </thead>
      <tbody class="bg-white divide-y divide-gray-200">
        @forelse($domains as $d)
        <tr>
          <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
            <a class="hover:underline" href="{{ route('admin.domains.show',$d) }}">{{ $d->domain }}</a>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ optional($d->user)->email }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $d->score_last ?? '—' }}</td>
          <td class="px-6 py-4 whitespace-nowrap">
            @php $bl = $d->blacklist_status ?: 'not-checked'; @endphp
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
             {{ $bl === 'listed' ? 'bg-red-100 text-red-800' : ($bl==='clean' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800') }}">
              {{ ucfirst($bl) }}
            </span>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $d->last_scanned_at? $d->last_scanned_at->diffForHumans():'Never' }}</td>
          <td class="px-6 py-4 whitespace-nowrap">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $d->status==='active'?'bg-green-100 text-green-800':($d->status==='pending'?'bg-yellow-100 text-yellow-800':'bg-gray-100 text-gray-800') }}">
              {{ ucfirst($d->status) }}
            </span>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
            <a href="{{ route('admin.domains.show',$d) }}" class="text-red-600 hover:text-red-900">View</a>
            <form action="{{ route('admin.domains.scan',$d) }}" method="post" class="inline">@csrf
              <button class="text-blue-600 hover:text-blue-900">Scan</button>
            </form>
            <form action="{{ route('admin.domains.blacklist',$d) }}" method="post" class="inline">@csrf
              <button class="text-purple-600 hover:text-purple-900">Blacklist</button>
            </form>
            <form action="{{ route('admin.domains.destroy',$d) }}" method="post" class="inline" onsubmit="return confirm('Delete domain?')">
              @csrf @method('DELETE')
              <button class="text-red-600 hover:text-red-900">Delete</button>
            </form>
          </td>
        </tr>
        @empty
        <tr><td colspan="7" class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">No domains found.</td></tr>
        @endforelse
      </tbody>
    </table>
  </div>
</div>

<div class="mt-4">
  {{ $domains->links() }}
</div>
@endsection