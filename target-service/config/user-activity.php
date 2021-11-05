<?php

return [
    'activated'        => true, // active/inactive all logging
    'middleware'       => ['web', 'auth'],
    'route_path'       => 'admin/user-activity',
<<<<<<< HEAD
<<<<<<< HEAD
    'admin_panel_path' => 'home',
=======
    'admin_panel_path' => '/',
>>>>>>> Add haruncpi/laravel-user-activity
=======
    'admin_panel_path' => 'home',
>>>>>>> Add Again Haruncpi
    'delete_limit'     => 7, // default 7 days

    'model' => [
        'user' => "App\User"
    ],

    'log_events' => [
        'on_create'     => false,
        'on_edit'       => true,
        'on_delete'     => true,
        'on_login'      => true,
        'on_lockout'    => true
    ]
];
