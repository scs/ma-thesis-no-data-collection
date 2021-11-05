<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('home');
});

Auth::routes();

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');
<<<<<<< HEAD
<<<<<<< HEAD
Route::post('login_with_visitor', [App\Http\Controllers\LoginController::class, 'authenticate'])->name('my_login');
=======
>>>>>>> Add target-service
=======
Route::post('login_with_visitor', [App\Http\Controllers\LoginController::class, 'authenticate'])->name('my_login');
>>>>>>> Logging UserID

Route::middleware(['auth'])->group(function () {

});
