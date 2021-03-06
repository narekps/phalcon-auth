<?php

return [
    'application' => [ // Global application configs

    ],
    'auth' => [ // This component configs
        'passwordCost' => 14, // optional, default 14
        'identityClass' => '\App\Models\Users', // required, @see \narekps\PhalconAuth\IdentityInterface
        'sessionKey' => 'auth', // required
        'cryptSalt' => 'CHANGE ME', // required, if not set \Phalcon\Cryp::key, TODO: change in production!
        'cookie' => [
            'name' => 'auth', // required
            'expire' => 3600 * 24 * 30, // optional, default 30 days
            'path' => '/', // optional default "/"
            'domain' => 'example.com', // optional, no default
            'secure' => false, // optional, default false
            'httpOnly' => false, // optional, default false
        ],
    ],
];
