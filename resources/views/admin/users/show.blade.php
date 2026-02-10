@extends('admin.layouts.app')

@section('page-title', 'User · '.$user->email)

@section('content')
<div class="mb-6 flex items-center justify-between">
  <a href="{{ route('admin.users.index') }}" class="text-sm text-gray-500 hover:underline">← Back to users</a>
  <div class="flex items-center space-x-2">
    @if($user->status !== 'banned')
      <form action="{{ route('admin.users.ban', $user) }}" method="post" onsubmit="return confirm('Ban this user? Their active subscriptions will be canceled.')">
        @csrf
        <button class="inline-flex items-center px-3 py-1.5 border border-red-300 rounded-md text-sm font-medium text-red-700 bg-red-50 hover:bg-red-100">
          <i data-lucide="ban" class="w-4 h-4 mr-1"></i> Ban
        </button>
      </form>
    @endif
    @if($user->status === 'banned' || $user->status === 'suspended')
      <form action="{{ route('admin.users.reactivate', $user) }}" method="post">
        @csrf
        <button class="inline-flex items-center px-3 py-1.5 border border-green-300 rounded-md text-sm font-medium text-green-700 bg-green-50 hover:bg-green-100">
          <i data-lucide="check-circle" class="w-4 h-4 mr-1"></i> Reactivate
        </button>
      </form>
    @endif
    @if($user->status === 'active')
      <form action="{{ route('admin.users.suspend', $user) }}" method="post" onsubmit="return confirm('Suspend this user?')">
        @csrf
        <button class="inline-flex items-center px-3 py-1.5 border border-yellow-300 rounded-md text-sm font-medium text-yellow-700 bg-yellow-50 hover:bg-yellow-100">
          <i data-lucide="pause-circle" class="w-4 h-4 mr-1"></i> Suspend
        </button>
      </form>
    @endif
    <form action="{{ route('admin.users.destroy', $user) }}" method="post" onsubmit="return confirm('Permanently delete this user? This cannot be undone.')">
      @csrf @method('DELETE')
      <button class="inline-flex items-center px-3 py-1.5 border border-red-300 rounded-md text-sm font-medium text-red-700 bg-white hover:bg-red-50">
        <i data-lucide="trash-2" class="w-4 h-4 mr-1"></i> Delete
      </button>
    </form>
  </div>
</div>

@if(session('success'))
  <div class="mb-4 rounded-md bg-green-50 p-4">
    <div class="flex">
      <i data-lucide="check-circle" class="h-5 w-5 text-green-400 mr-2"></i>
      <p class="text-sm text-green-700">{{ session('success') }}</p>
    </div>
  </div>
@endif

{{-- Top: Profile + Stats + Quick Actions --}}
<div class="grid gap-6 md:grid-cols-3 mb-6">
  {{-- Profile Card --}}
  <div class="bg-white shadow overflow-hidden sm:rounded-lg md:col-span-2">
    <div class="px-4 py-5 sm:px-6 flex items-center justify-between">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Profile</h3>
      @php
        $statusColors = [
          'active'    => 'bg-green-100 text-green-800',
          'inactive'  => 'bg-gray-100 text-gray-800',
          'suspended' => 'bg-yellow-100 text-yellow-800',
          'banned'    => 'bg-red-100 text-red-800',
        ];
        $statusClass = $statusColors[$user->status] ?? 'bg-gray-100 text-gray-800';
      @endphp
      <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $statusClass }}">
        {{ ucfirst($user->status ?? 'active') }}
      </span>
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
          <dt class="text-sm font-medium text-gray-500">Registered</dt>
          <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $user->created_at->format('M d, Y H:i') }}</dd>
        </div>
        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
          <dt class="text-sm font-medium text-gray-500">Email Verified</dt>
          <dd class="mt-1 text-sm sm:mt-0 sm:col-span-2">
            @if($user->email_verified_at)
              <span class="text-green-600">{{ $user->email_verified_at->format('M d, Y H:i') }}</span>
            @else
              <span class="text-red-600">Not verified</span>
            @endif
          </dd>
        </div>
      </dl>
    </div>

    {{-- Edit Form --}}
    <form action="{{ route('admin.users.update', $user) }}" method="post" class="px-4 py-5 sm:px-6 border-t border-gray-200">
      @csrf @method('PATCH')
      <h4 class="text-sm font-semibold text-gray-700 mb-3">Edit User</h4>
      <div class="grid md:grid-cols-3 gap-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">Name</label>
          <input class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm" name="name" value="{{ old('name', $user->name) }}">
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Role</label>
          <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm" name="role">
            @foreach(['user','admin','superadmin'] as $r)
              <option value="{{ $r }}" @selected($user->role===$r)>{{ ucfirst($r) }}</option>
            @endforeach
          </select>
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">Status</label>
          <select class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm" name="status">
            <option value="active" @selected($user->status==='active')>Active</option>
            <option value="inactive" @selected($user->status==='inactive')>Inactive</option>
            <option value="suspended" @selected($user->status==='suspended')>Suspended</option>
          </select>
        </div>
      </div>
      <div class="mt-3">
        <button class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">Save Changes</button>
      </div>
    </form>
  </div>

  {{-- Sidebar: Stats + Actions --}}
  <div class="space-y-6">
    {{-- Plan & Subscription --}}
    <div class="bg-white shadow overflow-hidden sm:rounded-lg">
      <div class="px-4 py-5 sm:px-6">
        <h3 class="text-lg leading-6 font-medium text-gray-900">Plan & Subscription</h3>
      </div>
      <div class="border-t border-gray-200 px-4 py-5 sm:p-6">
        <div class="space-y-3 text-sm">
          <div class="flex justify-between">
            <span class="text-gray-500">Current Plan</span>
            <span class="font-semibold {{ $plan ? 'text-red-600' : 'text-gray-500' }}">{{ $plan->name ?? 'Free' }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-500">Tier</span>
            <span class="font-medium">{{ ucfirst($user->currentTier()) }}</span>
          </div>
          @if($subscription)
            <div class="flex justify-between">
              <span class="text-gray-500">Status</span>
              <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium {{ $subscription->status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800' }}">
                {{ ucfirst($subscription->status) }}
              </span>
            </div>
            @if($plan)
              <div class="flex justify-between">
                <span class="text-gray-500">Price</span>
                <span class="font-medium">€{{ number_format($plan->price, 2) }}/{{ $plan->interval ?? 'mo' }}</span>
              </div>
            @endif
            @if($subscription->started_at)
              <div class="flex justify-between">
                <span class="text-gray-500">Started</span>
                <span>{{ $subscription->started_at->format('M d, Y') }}</span>
              </div>
            @endif
            @if($subscription->renews_at)
              <div class="flex justify-between">
                <span class="text-gray-500">Renews</span>
                <span>{{ $subscription->renews_at->format('M d, Y') }}</span>
              </div>
            @endif
          @endif
          <div class="flex justify-between">
            <span class="text-gray-500">Domain Limit</span>
            <span class="font-medium">{{ $user->domainsUsed() }} / {{ $user->domainLimit() }}</span>
          </div>
        </div>
      </div>
    </div>

    {{-- Quick Stats --}}
    <div class="bg-white shadow overflow-hidden sm:rounded-lg">
      <div class="px-4 py-5 sm:px-6">
        <h3 class="text-lg leading-6 font-medium text-gray-900">Stats</h3>
      </div>
      <div class="border-t border-gray-200 px-4 py-5 sm:p-6">
        <div class="space-y-3 text-sm">
          <div class="flex justify-between">
            <span class="text-gray-500">Domains</span>
            <span class="font-medium">{{ $domainsCount }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-500">Scans</span>
            <span class="font-medium">{{ $scansCount }}</span>
          </div>
        </div>
        <div class="mt-5 space-y-2">
          <form action="{{ route('admin.impersonate.start', $user) }}" method="post">@csrf
            <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
              <i data-lucide="user-check" class="w-4 h-4 mr-2"></i> Impersonate
            </button>
          </form>
          @if(session('impersonator_id'))
          <form action="{{ route('admin.impersonate.stop') }}" method="post">@csrf
            <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
              <i data-lucide="user-x" class="w-4 h-4 mr-2"></i> Stop Impersonating
            </button>
          </form>
          @endif
        </div>
      </div>
    </div>

    {{-- Reset Password --}}
    <div class="bg-white shadow overflow-hidden sm:rounded-lg">
      <div class="px-4 py-5 sm:px-6">
        <h3 class="text-lg leading-6 font-medium text-gray-900">Reset Password</h3>
      </div>
      <div class="border-t border-gray-200 px-4 py-5 sm:p-6">
        <form action="{{ route('admin.users.reset-password', $user) }}" method="post">
          @csrf
          <div class="space-y-3">
            <input type="password" name="password" placeholder="New password" required class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm">
            <input type="password" name="password_confirmation" placeholder="Confirm password" required class="block w-full rounded-md border-gray-300 shadow-sm focus:border-red-500 focus:ring-red-500 text-sm">
            <button class="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
              Reset Password
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

{{-- Subscriptions History --}}
<div class="bg-white shadow overflow-hidden sm:rounded-lg mb-6">
  <div class="px-4 py-5 sm:px-6">
    <h3 class="text-lg leading-6 font-medium text-gray-900">Subscription History</h3>
  </div>
  <div class="overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200">
      <thead class="bg-gray-50">
        <tr>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Plan</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Renews</th>
          <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Canceled</th>
          <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
        </tr>
      </thead>
      <tbody class="bg-white divide-y divide-gray-200">
        @forelse($allSubscriptions as $sub)
        <tr>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">#{{ $sub->id }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ $sub->plan->name ?? '—' }}</td>
          <td class="px-6 py-4 whitespace-nowrap">
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $sub->status === 'active' ? 'bg-green-100 text-green-800' : ($sub->status === 'canceled' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800') }}">
              {{ ucfirst($sub->status) }}
            </span>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $sub->started_at?->format('M d, Y') ?? '—' }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $sub->renews_at?->format('M d, Y') ?? '—' }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $sub->canceled_at?->format('M d, Y') ?? '—' }}</td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm">
            @if($sub->status === 'active')
              <form action="{{ route('admin.users.terminate-subscription', $user) }}" method="post" class="inline" onsubmit="return confirm('Terminate this subscription?')">
                @csrf
                <input type="hidden" name="subscription_id" value="{{ $sub->id }}">
                <button class="text-red-600 hover:text-red-900 font-medium">Terminate</button>
              </form>
            @else
              <span class="text-gray-400">—</span>
            @endif
          </td>
        </tr>
        @empty
        <tr>
          <td colspan="7" class="px-6 py-4 text-center text-sm text-gray-500">No subscriptions found.</td>
        </tr>
        @endforelse
      </tbody>
    </table>
  </div>
</div>

{{-- Bottom: Recent Domains + Recent Scans --}}
<div class="grid gap-6 md:grid-cols-2">
  {{-- Recent Domains --}}
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Domains ({{ $domainsCount }})</h3>
    </div>
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Scanned</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
          @forelse($domains as $domain)
          <tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
              <a href="{{ route('admin.domains.show', $domain) }}" class="text-red-600 hover:text-red-900">{{ $domain->domain }}</a>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm">
              @if($domain->score_last)
                @php
                  $sc = $domain->score_last;
                  $scClass = $sc >= 90 ? 'bg-green-100 text-green-800' : ($sc >= 70 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800');
                @endphp
                <span class="inline-flex px-2 py-0.5 rounded-full text-xs font-medium {{ $scClass }}">{{ $sc }}/100</span>
              @else
                <span class="text-gray-400">—</span>
              @endif
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $domain->last_scanned_at?->diffForHumans() ?? '—' }}</td>
          </tr>
          @empty
          <tr>
            <td colspan="3" class="px-6 py-4 text-center text-sm text-gray-500">No domains.</td>
          </tr>
          @endforelse
        </tbody>
      </table>
    </div>
  </div>

  {{-- Recent Scans --}}
  <div class="bg-white shadow overflow-hidden sm:rounded-lg">
    <div class="px-4 py-5 sm:px-6">
      <h3 class="text-lg leading-6 font-medium text-gray-900">Recent Scans ({{ $scansCount }})</h3>
    </div>
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
          @forelse($recentScans as $scan)
          <tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ $scan->domain->domain ?? '—' }}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $scan->getTypeLabel() }}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm">
              @if($scan->status === 'finished' && $scan->score)
                @php
                  $ssc = $scan->score;
                  $sscClass = $ssc >= 90 ? 'bg-green-100 text-green-800' : ($ssc >= 70 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800');
                @endphp
                <span class="inline-flex px-2 py-0.5 rounded-full text-xs font-medium {{ $sscClass }}">{{ $ssc }}/100</span>
              @else
                <span class="inline-flex px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">{{ ucfirst($scan->status) }}</span>
              @endif
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ $scan->created_at->diffForHumans() }}</td>
          </tr>
          @empty
          <tr>
            <td colspan="4" class="px-6 py-4 text-center text-sm text-gray-500">No scans.</td>
          </tr>
          @endforelse
        </tbody>
      </table>
    </div>
  </div>
</div>
@endsection
