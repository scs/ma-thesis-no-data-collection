<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
<<<<<<< HEAD
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
=======
>>>>>>> Add target-service

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
        $visitor = Tracker::currentSession();

        //$users = Tracker::onlineUsers();
        $users = "";
        return view('home', ['users' => $visitor]);
=======
        return view('home');
>>>>>>> Add target-service
    }
}
