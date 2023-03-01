<?php

namespace Nails\MFA\Model;

use Nails\MFA\Constants;
use Nails\Common\Model\Base;

class Token extends Base
{
    const TABLE             = NAILS_DB_PREFIX . 'mfa_token';
    const RESOURCE_NAME     = 'Token';
    const RESOURCE_PROVIDER = Constants::MODULE_SLUG;

    // --------------------------------------------------------------------------

    public function __construct()
    {
        parent::__construct();
        $this
            ->hasOne('user', 'User', \Nails\Auth\Constants::MODULE_SLUG);
    }
}
