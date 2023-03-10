<?php

namespace Nails\MFA\Event\Listener\User;

use App\Api\Controller\VirtualAdviser;
use Nails\Auth\Model\User;
use Nails\MFA\Constants;
use Nails\Auth\Events;
use Nails\Auth\Service\Authentication;
use Nails\MFA\Service\MultiFactorAuth;
use Nails\Common\Events\Subscription;
use Nails\Common\Exception\ValidationException;
use Nails\Common\Helper\Model\Expand;
use Nails\Factory;

class LogIn extends Subscription
{
    /**
     * LogIn constructor.
     */
    public function __construct()
    {
        $this
            ->setEvent(Events::USER_LOG_IN)
            ->setNamespace(Events::getEventNamespace())
            ->setCallback([$this, 'execute']);
    }

    // --------------------------------------------------------------------------

    public function execute(): void
    {
        /** @var MultiFactorAuth $oService */
        $oService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var User $oUserModel */
        $oUserModel = Factory::model('User', \Nails\Auth\Constants::MODULE_SLUG);

        $oService->authenticate(
            $oUserModel->activeUser(),
            $oUserModel->bIsRemembered()
        );
    }
}
