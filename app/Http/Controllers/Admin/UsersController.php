<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class UsersController extends Controller
{
    public function index(Request $request)
    {
        $q = User::query()
            ->select('id','name','email','role','status','created_at')
            ->when($request->keyword, fn($qr) =>
                $qr->where(function($w) use ($request) {
                    $w->where('name','like',"%{$request->keyword}%")
                      ->orWhere('email','like',"%{$request->keyword}%");
                })
            )
            ->when($request->role, fn($qr) => $qr->where('role', $request->role))
            ->when($request->status === 'active', fn($qr) => $qr->where('status', 'active'))
            ->when($request->status === 'inactive', fn($qr) => $qr->where('status', '!=', 'active'))
            ->orderBy($request->get('sort','created_at'), $request->get('dir','desc'));

        $users = $q->paginate(20)->withQueryString();

        return view('admin.users.index', compact('users'));
    }

    public function export(Request $request): StreamedResponse
    {
        $file = 'users_export_'.now()->format('Ymd_His').'.csv';

        $query = User::query()
            ->select('id','name','email','role','status','created_at');

        return response()->streamDownload(function() use ($query) {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['ID','Name','Email','Role','Status','Created']);
            $query->orderBy('id')->chunk(500, function($chunk) use ($out) {
                foreach ($chunk as $u) {
                    fputcsv($out, [$u->id, $u->name, $u->email, $u->role, $u->status, $u->created_at]);
                }
            });
            fclose($out);
        }, $file, ['Content-Type' => 'text/csv']);
    }

    public function create()
    {
        return view('admin.users.create');
    }

    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'required|string|in:user,admin,superadmin',
            'status' => 'required|string|in:active,inactive,suspended',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'role' => $request->role,
            'status' => $request->status,
            'email_verified_at' => now(), // Auto-verify admin created users
        ]);

        return redirect()->route('admin.users.index')->with('success', 'User created successfully');
    }

    public function show(User $user)
    {
        $domainsCount = $user->domains()->count() ?? 0;
        $scansCount   = $user->scans()->count() ?? 0;
        return view('admin.users.show', compact('user','domainsCount','scansCount'));
    }

    public function edit(User $user)
    {
        return view('admin.users.edit', compact('user'));
    }

    public function update(Request $request, User $user)
    {
        $request->validate([
            'name'   => 'sometimes|string|max:255',
            'role'   => 'sometimes|string|in:user,admin,superadmin',
            'status' => 'sometimes|string|in:active,inactive,suspended',
        ]);

        $user->fill($request->only('name','role','status'))->save();

        return back()->with('success','User updated');
    }

    public function destroy(User $user)
    {
        // Soft delete if enabled; otherwise caution!
        $user->delete();
        return redirect()->route('admin.users.index')->with('success','User deleted');
    }
}
