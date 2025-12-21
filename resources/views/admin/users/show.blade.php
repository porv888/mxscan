@extends('admin.layouts.app')

@section('page-title', 'User · '.$user->email)

@section('content')
<div class="mb-6">
  <a href="{{ route('admin.users.index') }}" class="text-sm text-gray-500 hover:underline">← Back to users</a>
</div>

<div class="grid gap-6 md:grid-cols-3">
  <div class="bg-white shadow overflow-hidden sm:rounded-lg md:col-span-2">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Profile</h3>
    </div>
    <div class="border-t border-gray-200 px-4 py-5 sm:p-0">
      <dl class="sm:divide-y sm:divide-gray-200">
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Name</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $user->name }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Email</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $user->email }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Role</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ ucfirst($user->role) }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Status</dt>
          <dd class="mt-1 sm:mt-0 sm:col-span-2">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $user->status === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800' }}">
              {{ ucfirst($user->status ?? 'active') }}
            </span>
          </dd>
        </div>
      </dl>
    </div>

    <form action="{{ route('admin.users.update',$user) }}" method="post" class="px-4 py-5 sm:px-6 border-t border-gray-200">
      @csrf @method('PATCH')
      <div class="grid md:grid-cols-3 gap-3">
        <input class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="name" value="{{ old('name',$user->name) }}" placeholder="Name">
        <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="role">
          @foreach(['user','admin','superadmin'] as $r)
            <option value="{{ $r }}" @selected($user->role===$r)>{{ ucfirst($r) }}</option>
          @endforeach
        </select>
        <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500" name="status">
          <option value="active" @selected($user->status==='active')>Active</option>
          <option value="inactive" @selected($user->status==='inactive')>Inactive</option>
          <option value="suspended" @selected($user->status==='suspended')>Suspended</option>
        </select>
      </div>
      <div class="mt-4">
        <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Save Changes</button>
      </div>
    </form>
  </div>

  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Stats</h3>
    </div>
    <div class="border-t border-gray-200 px-4 py-5 sm:p-6">
      <div class="space-y-4 text-sm">
        <div class="flex justify-between">
          <span class="text-gray-500">Domains:</span>
          <span class="font-medium">{{ $domainsCount }}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-500">Scans:</span>
          <span class="font-medium">{{ $scansCount }}</span>
        </div>
      </div>
      <div class="mt-6 space-y-2">
        <form action="{{ route('admin.impersonate.start',$user) }}" method="post">@csrf
          <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
            <i data-lucide="user-check" class="w-4 h-4 mr-2"></i>
            Impersonate
          </button>
        </form>
        @if(session('impersonator_id'))
        <form action="{{ route('admin.impersonate.stop') }}" method="post">@csrf
          <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
            <i data-lucide="user-x" class="w-4 h-4 mr-2"></i>
            Stop Impersonating
          </button>
        </form>
        @endif
      </div>
    </div>
  </div>
</div>
@endsection
