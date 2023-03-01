<?php

namespace Nails\MFA\Service;

use Nails\Common\Model\BaseDriver;
use Nails\MFA\Constants;
use Nails\MFA\Interfaces\Authentication\Driver;

/**
 * Class AuthenticationDriver
 *
 * @package Nails\MFA\Service
 */
class AuthenticationDriver extends BaseDriver
{
    protected $sModule        = Constants::MODULE_SLUG;
    protected $sType          = 'authentication';
    protected $sMustImplement = Driver::class;
}
