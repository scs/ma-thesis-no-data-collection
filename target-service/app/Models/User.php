<?php

namespace App\Models;

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use Haruncpi\LaravelUserActivity\Traits\Loggable;
=======
>>>>>>> Add target-service
=======
use Haruncpi\LaravelUserActivity\Traits\Loggable;
>>>>>>> Add Again Haruncpi
=======
use Haruncpi\LaravelUserActivity\Traits\Loggable;
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    use HasApiTokens, HasFactory, Notifiable, Loggable;
=======
    use HasApiTokens, HasFactory, Notifiable;
>>>>>>> Add target-service
=======
    use HasApiTokens, HasFactory, Notifiable, Loggable;
>>>>>>> Add Again Haruncpi
=======
    use HasApiTokens, HasFactory, Notifiable, Loggable;
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67

    /**
     * The attributes that are mass assignable.
     *
     * @var string[]
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
     * @var arraygit
=======
     * @var array
>>>>>>> Add target-service
=======
     * @var arraygit
>>>>>>> Added antonioribeiro tracker
=======
     * @var arraygit
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    protected $connection = 'mysql';
    public function getIsAdminAttribute()
    {
        return auth()->id()==1;
    }
=======
>>>>>>> Add target-service
=======
=======
    protected $connection = 'mysql';
>>>>>>> Tracker update
=======
    protected $connection = 'mysql';
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
    public function getIsAdminAttribute()
    {
        return auth()->id()==1;
    }
<<<<<<< HEAD
>>>>>>> Added antonioribeiro tracker
=======
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
}
