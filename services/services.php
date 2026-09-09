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
        'MultiFactorAuth'      => function (): Service\MultiFactorAuth {
            if (class_exists('\App\MFA\Service\MultiFactorAuth')) {
                return new \App\MFA\Service\MultiFactorAuth();
            } else {
                return new Service\MultiFactorAuth();
            }
        },
        'Logger'               => function (): Service\Logger {
            if (class_exists('\App\MFA\Service\Logger')) {
                return new \App\MFA\Service\Logger();
            } else {
                return new Service\Logger();
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
        'GroupPolicy' => function (): Model\GroupPolicy {
            if (class_exists('\App\MFA\Model\GroupPolicy')) {
                return new \App\MFA\Model\GroupPolicy();
            } else {
                return new Model\GroupPolicy();
            }
        },
        'UserMethod' => function (): Model\UserMethod {
            if (class_exists('\App\MFA\Model\UserMethod')) {
                return new \App\MFA\Model\UserMethod();
            } else {
                return new Model\UserMethod();
            }
        },
    ],
    'resources' => [
        'Token' => function ($resource, $model): Resource\Token {
            if (class_exists('\App\MFA\Resource\Token')) {
                return new \App\MFA\Resource\Token($resource, $model);
            } else {
                return new Resource\Token($resource, $model);
            }
        },
        'GroupPolicy' => function ($resource, $model): Resource\GroupPolicy {
            if (class_exists('\App\MFA\Resource\GroupPolicy')) {
                return new \App\MFA\Resource\GroupPolicy($resource, $model);
            } else {
                return new Resource\GroupPolicy($resource, $model);
            }
        },
        'UserMethod' => function ($resource, $model): Resource\UserMethod {
            if (class_exists('\App\MFA\Resource\UserMethod')) {
                return new \App\MFA\Resource\UserMethod($resource, $model);
            } else {
                return new Resource\UserMethod($resource, $model);
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
