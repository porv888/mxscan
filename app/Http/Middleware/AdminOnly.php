<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AdminOnly
{
    public function handle(Request $request, Closure $next)
    {
        $user = $request->user();
        if (! $user || ! $user->role || ! in_array($user->role, ['admin','superadmin'])) {
            abort(403, 'Admins only');
        }
        return $next($request);
    }
}
