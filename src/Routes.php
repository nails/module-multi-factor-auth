<?php

namespace Nails\MFA;

use Nails\Common\Interfaces\RouteGenerator;

class Routes implements RouteGenerator
{
    /**
     * @return array<string, string>
     */
    public static function generate(): array
    {
        return [
            'mfa'        => 'mfa/index',
            'mfa/manage' => 'mfa/manage',
        ];
    }
}
