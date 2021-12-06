<?php

return [
    'activated'        => true, // active/inactive all logging
    'middleware'       => ['web', 'auth'],
    'route_path'       => 'admin/user-activity',
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    'admin_panel_path' => 'home',
=======
    'admin_panel_path' => '/',
>>>>>>> Add haruncpi/laravel-user-activity
=======
    'admin_panel_path' => 'home',
>>>>>>> Add Again Haruncpi
=======
    'admin_panel_path' => 'home',
>>>>>>> 1ba10e1cba7b340282a7448f129c895f9d8e6a67
    'delete_limit'     => 7, // default 7 days

    'model' => [
        'user' => "App\Models\User"
    ],

    'log_events' => [
        'on_create'     => false,
        'on_edit'       => true,
        'on_delete'     => true,
        'on_login'      => true,
        'on_lockout'    => true
    ]
];
