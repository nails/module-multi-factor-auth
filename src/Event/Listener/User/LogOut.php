<?php

namespace Nails\MFA\Event\Listener\User;

use Nails\Auth\Events;
use Nails\Common\Events\Subscription;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Service\Logger;
use Nails\MFA\Service\MultiFactorAuth;

class LogOut extends Subscription
{
    /**
     * LogOut constructor.
     */
    public function __construct()
    {
        $this
            ->setEvent(Events::USER_LOG_OUT)
            ->setNamespace(Events::getEventNamespace())
            ->setCallback([$this, 'execute']);
    }

    // --------------------------------------------------------------------------

    public function execute(?int $iUserId = null): void
    {
        /** @var MultiFactorAuth $oService */
        $oService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Logger $oLogger */
        $oLogger = Factory::service('Logger', Constants::MODULE_SLUG);

        $bTrustSurvives = $oService->trustSurvivesLogout();

        $oLogger->info(sprintf(
            'Caught user logout event for #%s; discarding MFA cookies (trusted device survives: %s)',
            $iUserId ?: 'unknown',
            json_encode($bTrustSurvives)
        ));

        //  A half finished challenge is never worth keeping
        $oService->clearTokenCookie();

        /**
         * Signing out is taken as intent to end this device's trust, otherwise
         * the next person to sign in here skips the challenge. Sites which would
         * rather honour the full trust window can opt out with the
         * MFA_TRUST_SURVIVES_LOGOUT config property.
         */
        if (!$bTrustSurvives) {
            $oService->clearIsPrivilegedCookie();
        }
    }
}
