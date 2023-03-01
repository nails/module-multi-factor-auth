<?php

use Nails\MFA\Factory;
use Nails\MFA\Model;
use Nails\MFA\Resource;
use Nails\MFA\Service;

return [
    'services'  => [
        'AuthenticationDriver' => function (): Service\AuthenticationDriver {
            if (class_exists('\App\MFA\Service\AuthenticationDriver')) {
                return new \App\MFA\Service\AuthenticationDriver();
            } else {
                return new Service\AuthenticationDriver();
            }
        },
        'MultiFactorAuth' => function (): Service\MultiFactorAuth {
            if (class_exists('\App\MFA\Service\MultiFactorAuth')) {
                return new \App\MFA\Service\MultiFactorAuth();
            } else {
                return new Service\MultiFactorAuth();
            }
        },
    ],
    'models'    => [
        'Token' => function (): Model\Token {
            if (class_exists('\App\MFA\Model\Token')) {
                return new \App\MFA\Model\Token();
            } else {
                return new Model\Token();
            }
        },
    ],
    'resources' => [
        'Token' => function ($oObj): Resource\Token {
            if (class_exists('\App\MFA\Resource\Token')) {
                return new \App\MFA\Resource\Token($oObj);
            } else {
                return new Resource\Token($oObj);
            }
        },
    ],
    'factories' => [
        'EmailCode' => function (): Factory\Email\Code {
            if (class_exists('\App\Auth\MultiFactorAuth\Driver\Email\Factory\Email\Code')) {
                return new \App\Auth\MultiFactorAuth\Driver\Email\Factory\Email\Code();
            } else {
                return new Factory\Email\Code();
            }
        },
    ],
];
