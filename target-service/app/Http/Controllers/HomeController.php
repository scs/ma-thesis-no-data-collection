<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
<<<<<<< HEAD
<<<<<<< HEAD
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
=======
>>>>>>> Add target-service
=======
use PragmaRX\Tracker\Tracker;
>>>>>>> WIP: tracking User

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
<<<<<<< HEAD
<<<<<<< HEAD
        $visitor = Tracker::currentSession();

        //$users = Tracker::onlineUsers();
        $users = "";
        return view('home', ['users' => $visitor]);
=======
        return view('home');
>>>>>>> Add target-service
=======
        //$users = Tracker::onlineUsers();
        $users = "";
        return view('home', ['users' => $users]);
>>>>>>> WIP: tracking User
    }
}
