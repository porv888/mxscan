<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class ImpersonateController extends Controller
{
    public function start(User $user, Request $request)
    {
        $admin = $request->user();
        if (!in_array($admin->role, ['admin','superadmin'])) abort(403);
        session(['impersonate_id' => $user->id, 'impersonator_id'=>$admin->id]);
        auth()->login($user);
        return redirect('/dashboard')->with('success','Impersonating '.$user->email);
    }

    public function stop(Request $request)
    {
        $impersonatorId = session('impersonator_id');
        if ($impersonatorId) {
            session()->forget(['impersonate_id','impersonator_id']);
            auth()->loginUsingId($impersonatorId);
        }
        return redirect()->route('admin.users.index')->with('success','Stopped impersonation');
    }
}
