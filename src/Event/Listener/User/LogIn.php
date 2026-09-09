<?php

namespace Nails\MFA\Event\Listener\User;

use Nails\Auth\Events;
use Nails\Auth\Model\User;
use Nails\Common\Events\Subscription;
use Nails\Common\Service\UserFeedback;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Service\Logger;
use Nails\MFA\Service\MultiFactorAuth;
use Throwable;

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

    public function execute(\Nails\Auth\Resource\User $oUser): void
    {
        /** @var MultiFactorAuth $oService */
        $oService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Logger $oLogger */
        $oLogger = Factory::service('Logger', Constants::MODULE_SLUG);
        /** @var User $oUserModel */
        $oUserModel = Factory::model('User', \Nails\Auth\Constants::MODULE_SLUG);

        $oLogger->info(sprintf(
            'Caught user login event for #%s %s (%s); checking if MFA is required',
            $oUser->id,
            $oUser->name,
            $oUser->email
        ));

        try {

            $oService->authenticate(
                $oUserModel->activeUser(),
                $oUserModel->isRemembered()
            );

        } catch (Throwable $e) {

            /**
             * The user is logged in by the time this event fires, so letting the
             * exception surface would leave them signed in without ever being
             * challenged. Fail closed: sign them out and send them back to login.
             */

            $oLogger->error(sprintf(
                'MFA could not be applied to user #%s, signing them out: [%s] %s',
                $oUser->id,
                $e::class,
                $e->getMessage()
            ));

            /** @var UserFeedback $oUserFeedback */
            $oUserFeedback = Factory::service('UserFeedback');

            /**
             * Clearing the login data is enough to sign the user out, and unlike
             * Authentication::logout() it leaves the session intact; that destroys
             * the PHP session, which takes the feedback message below with it and
             * bounces the user back to a login form with no explanation.
             */
            if (isLoggedIn()) {
                $oUserModel->clearLoginData();
            }

            $oUserFeedback->error(
                $e instanceof MfaException
                    ? $e->getMessage()
                    : 'We could not complete your sign-in. Please try again.'
            );

            redirect(loginUrl(null));
        }
    }
}
