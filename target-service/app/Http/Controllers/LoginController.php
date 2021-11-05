<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;

class LoginController extends Controller{
    public function authenticate(Request $request){
        // Retrive Input
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            // if success login
            $visitor = Tracker::currentSession();
            //Log::info("this is visitor", (array) $visitor);
            $auth_id = Auth::id();
            if($visitor) {
                $visitor->user_id = $auth_id;
                $visitor->save();
            }

            return redirect('home');

            //return redirect()->intended('/details');
        }
        // if failed login
        return redirect('login');
    }
}
