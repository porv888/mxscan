<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/dashboard';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('auth')->only('logout');
    }

    /**
     * Show the application's login form.
     *
     * @return \Illuminate\View\View
     */
    public function showLoginForm()
    {
        Log::info('Login form accessed');
        
        // Ensure session is started
        if (!session()->isStarted()) {
            session()->start();
        }
        
        return view('auth.login');
    }

    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request)
    {
        Log::info('Login attempt', [
            'email' => $request->input('email'),
            'ip' => $request->ip(),
            'session_id' => session()->getId()
        ]);

        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            Log::info('Login successful', [
                'email' => $request->input('email'),
                'session_id' => session()->getId(),
                'user_id' => $this->guard()->user()->id
            ]);
            
            // Don't regenerate session - causes issues with cookie persistence
            // if ($request->hasSession()) {
            //     $request->session()->regenerate();
            // }

            $this->clearLoginAttempts($request);

            if ($response = $this->authenticated($request, $this->guard()->user())) {
                return $response;
            }

            return $request->wantsJson()
                        ? new \Illuminate\Http\JsonResponse([], 204)
                        : redirect()->intended($this->redirectPath());
        }

        Log::warning('Login failed', ['email' => $request->input('email')]);

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        $credentials = $this->credentials($request);
        
        // Use standard Laravel authentication but save session before
        $sessionId = $request->session()->getId();
        
        $result = $this->guard()->attempt(
            $credentials, $request->filled('remember')
        );
        
        if ($result) {
            // Force session ID back to original to prevent cookie mismatch
            $request->session()->setId($sessionId);
            $request->session()->save();
        }
        
        return $result;
    }

    /**
     * The user has been authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        Log::info('User authenticated', [
            'user_id' => $user->id,
            'email' => $user->email,
            'verified' => $user->hasVerifiedEmail()
        ]);
        
        // Redirect to verification notice if email is not verified
        if (!$user->hasVerifiedEmail()) {
            Log::info('Redirecting to verification notice');
            return redirect()->route('verification.notice');
        }

        // Otherwise redirect to dashboard
        Log::info('Redirecting to dashboard');
        return redirect()->intended($this->redirectPath());
    }
}
