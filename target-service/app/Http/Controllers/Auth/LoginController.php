<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use Illuminate\Support\Facades\Auth;
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
=======
>>>>>>> Add target-service
=======
use Illuminate\Support\Facades\Auth;
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
>>>>>>> Logging UserID
=======
use Illuminate\Support\Facades\Auth;
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67

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
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }
}
