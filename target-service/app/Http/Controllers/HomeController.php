<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
=======
>>>>>>> Add target-service
=======
use PragmaRX\Tracker\Tracker;
>>>>>>> WIP: tracking User
=======
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
>>>>>>> Logging UserID
=======
use PragmaRX\Tracker\Vendor\Laravel\Facade as Tracker;
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67

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
=======
=======
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
        $visitor = Tracker::currentSession();

        //$users = Tracker::onlineUsers();
        $users = "";
        return view('home', ['users' => $visitor]);
<<<<<<< HEAD
>>>>>>> Logging UserID
=======
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
    }
}
