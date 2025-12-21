@extends('admin.layouts.app')

@section('page-title', 'Users')

@section('content')
<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-semibold">Users</h1>
  <div class="space-x-2">
    <a href="{{ route('admin.users.export', request()->query()) }}" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
      <i data-lucide="download" class="w-4 h-4 mr-2"></i>
      Export CSV
    </a>
  </div>
</div>

<form method="get" class="grid md:grid-cols-4 gap-3 mb-4">
  <input type="text" name="keyword" value="{{ request('keyword') }}" placeholder="Search name/email" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500">
  <select name="role" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500">
    <option value="">All roles</option>
    @foreach(['user','admin','superadmin'] as $r)
      <option value="{{ $r }}" @selected(request('role')===$r)>{{ ucfirst($r) }}</option>
    @endforeach
  </select>
  <select name="status" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500">
    <option value="">All statuses</option>
    <option value="active" @selected(request('status')==='active')>Active</option>
    <option value="inactive" @selected(request('status')==='inactive')>Inactive</option>
  </select>
  <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Filter</button>
</form>

<div class="bg-white shadow overflow-hidden sm:rounded-md">
  <div class="overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
          <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
        </tr>
      </thead>
      <tbody class="bg-white divide-y divide-gray-200">
        @forelse($users as $u)
        <tr>
          <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ $u->name }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $u->email }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ ucfirst($u->role) }}</td>
          <td class="px-6 py-4 whitespace-nowrap">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $u->status === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800' }}">
              {{ ucfirst($u->status ?? 'active') }}
            </span>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $u->created_at->format('Y-m-d') }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
            <a href="{{ route('admin.users.show',$u) }}" class="text-red-600 hover:text-red-900">View</a>
            <form action="{{ route('admin.impersonate.start',$u) }}" method="post" class="inline">@csrf
              <button class="text-blue-600 hover:text-blue-900">Impersonate</button>
            </form>
            <form action="{{ route('admin.users.destroy',$u) }}" method="post" class="inline" onsubmit="return confirm('Delete user?')">
              @csrf @method('DELETE')
              <button class="text-red-600 hover:text-red-900">Delete</button>
            </form>
          </td>
        </tr>
        @empty
        <tr>
          <td colspan="6" class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 text-center">No users found.</td>
        </tr>
        @endforelse
      </tbody>
    </table>
  </div>
</div>

<div class="mt-4">
  {{ $users->links() }}
</div>
@endsection