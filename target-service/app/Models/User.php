<?php

namespace App\Models;

<<<<<<< HEAD
use Haruncpi\LaravelUserActivity\Traits\Loggable;
=======
>>>>>>> Add target-service
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
<<<<<<< HEAD
    use HasApiTokens, HasFactory, Notifiable, Loggable;
=======
    use HasApiTokens, HasFactory, Notifiable;
>>>>>>> Add target-service

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
     * @var arraygit
=======
     * @var array
>>>>>>> Add target-service
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];
<<<<<<< HEAD
    protected $connection = 'mysql';
    public function getIsAdminAttribute()
    {
        return auth()->id()==1;
    }
=======
>>>>>>> Add target-service
}
