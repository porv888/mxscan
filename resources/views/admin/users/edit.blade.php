@extends('admin.layouts.app')

@section('page-title', 'Edit User')

@section('content')
<div class="max-w-2xl mx-auto">
    <div class="bg-white shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
            <div class="mb-4">
                <h3 class="text-lg leading-6 font-medium text-gray-900">Edit User</h3>
                <p class="mt-1 text-sm text-gray-600">Update user information.</p>
            </div>

            <form method="POST" action="{{ route('admin.users.update', $user) }}" class="space-y-6">
                @csrf
                @method('PATCH')

                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700">Name</label>
                    <input type="text" name="name" id="name" value="{{ old('name', $user->name) }}" required
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500">
                    @error('name')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                    <input type="email" name="email" id="email" value="{{ $user->email }}" disabled
                           class="mt-1 block w-full border-gray-300 rounded-md shadow-sm bg-gray-50 text-gray-500">
                    <p class="mt-1 text-sm text-gray-500">Email cannot be changed</p>
                </div>

                <div>
                    <label for="role" class="block text-sm font-medium text-gray-700">Role</label>
                    <select name="role" id="role" required
                            class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500">
                        <option value="user" {{ old('role', $user->role) === 'user' ? 'selected' : '' }}>User</option>
                        <option value="admin" {{ old('role', $user->role) === 'admin' ? 'selected' : '' }}>Admin</option>
                        <option value="superadmin" {{ old('role', $user->role) === 'superadmin' ? 'selected' : '' }}>Super Admin</option>
                    </select>
                    @error('role')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <div>
                    <label for="status" class="block text-sm font-medium text-gray-700">Status</label>
                    <select name="status" id="status" required
                            class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500">
                        <option value="active" {{ old('status', $user->status) === 'active' ? 'selected' : '' }}>Active</option>
                        <option value="inactive" {{ old('status', $user->status) === 'inactive' ? 'selected' : '' }}>Inactive</option>
                        <option value="suspended" {{ old('status', $user->status) === 'suspended' ? 'selected' : '' }}>Suspended</option>
                    </select>
                    @error('status')
                        <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                    @enderror
                </div>

                <div class="bg-gray-50 p-4 rounded-md">
                    <h4 class="text-sm font-medium text-gray-900 mb-2">Account Information</h4>
                    <div class="text-sm text-gray-600 space-y-1">
                        <p><strong>Created:</strong> {{ $user->created_at->format('M j, Y g:i A') }}</p>
                        <p><strong>Last Updated:</strong> {{ $user->updated_at->format('M j, Y g:i A') }}</p>
                        @if($user->email_verified_at)
                            <p><strong>Email Verified:</strong> {{ $user->email_verified_at->format('M j, Y g:i A') }}</p>
                        @else
                            <p><strong>Email:</strong> <span class="text-orange-600">Not verified</span></p>
                        @endif
                    </div>
                </div>

                <div class="flex justify-end space-x-3">
                    <a href="{{ route('admin.users.show', $user) }}" 
                       class="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        Cancel
                    </a>
                    <button type="submit" 
                            class="bg-red-600 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                        Update User
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection
