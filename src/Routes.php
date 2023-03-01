<?php

/**
 * Generates Auth routes
 *
 * @package     Nails
 * @subpackage  module-auth
 * @category    Controller
 * @author      Nails Dev Team
 * @link
 */

namespace Nails\MFA;

use Nails\Common\Interfaces\RouteGenerator;

class Routes implements RouteGenerator
{
    public static function generate(): array
    {
        return [
            'mfa/(.+)' => 'mfa/index',
        ];
    }
}
