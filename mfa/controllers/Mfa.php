<?php

use App\Controller;
use Nails\Auth;
use Nails\Common\Exception\AssetException;
use Nails\Common\Exception\Encrypt\DecodeException;
use Nails\Common\Exception\EnvironmentException;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Exception\ModelException;
use Nails\Common\Exception\NailsException;
use Nails\Common\Exception\ViewNotFoundException;
use Nails\Common\Service;
use Nails\Config;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Exception;
use Nails\MFA\Interfaces;
use Nails\MFA\Model;
use Nails\MFA\Resource;
use Nails\MFA\Service\Logger;
use Nails\MFA\Service\MultiFactorAuth;

class Mfa extends Controller\Base
{
    private const SESSION_PENDING_SETUP = 'mfa-manage-pending';

    private Logger $oLogger;

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function __construct()
    {
        parent::__construct();
        $this->oLogger = Factory::service('Logger', Constants::MODULE_SLUG);

        /** @var Service\Output $oOutput */
        $oOutput = Factory::service('Output');
        $oOutput
            ->setHeader('Referrer-Policy: no-referrer')
            ->setHeader('Cache-Control: no-store');
    }

    // --------------------------------------------------------------------------

    /**
     * @return void
     * @throws Exception\MfaException
     * @throws ReflectionException
     * @throws DecodeException
     * @throws EnvironmentException
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    public function index()
    {
        /** @var Service\Input $oInput */
        $oInput = Factory::service('Input');
        /** @var Service\UserFeedback $oUserFeedback */
        $oUserFeedback = Factory::service('UserFeedback');
        /** @var MultiFactorAuth $oMfaService */
        $oMfaService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);

        // --------------------------------------------------------------------------

        try {

            if (isLoggedIn()) {
                throw new Exception\TokenException('User is already logged in');
            }

            $oToken = $oMfaService->getTokenFromCookie();
            $oUser  = $oToken->user();

            if ($oInput::post('action') === 'verify') {

                $this->log('User is attempting to verify');

                $oDriver = $oMfaService->selectDriver($oUser, $oToken);
                if (!$oDriver) {
                    throw new Exception\MfaException('No MFA driver is available for this account.');
                }

                try {

                    $oMfaService->registerFailedAttempt($oToken);
                    $oDriver->validate($oToken, (string) $oInput::post('code'));

                    if (
                        $oToken->getData($oMfaService::TOKEN_DATA_KEY_IS_SETUP)
                        && !$oMfaService->getUserMethod($oUser, (string) $oDriver->getSlug())
                    ) {
                        $oMfaService->enrollMethod(
                            $oUser,
                            (string) $oDriver->getSlug(),
                            $oDriver->setupComplete($oUser, '', (object) []),
                            true
                        );
                    }

                    $sRedirectUrl = $oMfaService->completeChallenge(
                        $oToken,
                        (bool) $oInput::post('remember')
                    );

                    $this->log(sprintf(
                        'User verified successfully, redirecting to "%s"',
                        $sRedirectUrl
                    ));

                    redirect($sRedirectUrl);

                } catch (Exception\InvalidCodeException $e) {
                    $this->log(sprintf(
                        'Caught exception: [%s] %s',
                        $e::class,
                        $e->getMessage()
                    ));
                    $oUserFeedback->error($e->getMessage());
                    $this->renderForm($oDriver, $oToken, $oMfaService);
                }

            } elseif ($oInput::post('action') === 'resend') {

                $this->log('User requested another verification code');

                /**
                 * The challenge is kept intact; discarding it here would lose the
                 * driver the user picked (and any setup in progress), and would
                 * spend one of their hourly challenges on a resend.
                 */
                $oDriver = $oMfaService->selectDriver($oUser, $oToken);
                if (!$oDriver) {
                    throw new Exception\MfaException('No MFA driver is available for this account.');
                }

                if (!$oDriver->canTryAgain()) {
                    $oUserFeedback->error('This verification method cannot issue another code.');

                } elseif ($oMfaService->claimResend($oToken)) {
                    $oDriver->resend($oToken, $oUserFeedback);

                } else {
                    $this->log('Resend allowance for this token is exhausted');
                    $oUserFeedback->error(
                        'You have requested too many codes. Please use the most recent one, or sign in again.'
                    );
                }

                $this->renderForm($oDriver, $oToken, $oMfaService);
                $oDriver->postForm($oToken);

            } elseif ($oInput::post('action') === 'setup_back') {

                $this->log('User is choosing a different MFA setup method');

                /**
                 * Reached from a challenge as well as from setup: a user whose only
                 * enrolled method will not let them in enrolls their way out. Either
                 * way the token becomes a setup one, so the driver they land on has
                 * to be demonstrated before completeChallenge() signs them in.
                 */
                $oMfaService->clearPendingSetup($oToken);
                $oToken->setData((object) [
                    $oMfaService::TOKEN_DATA_KEY_DRIVER  => null,
                    $oMfaService::TOKEN_DATA_KEY_IS_SETUP => true,
                ]);
                $this->renderSetup($oToken, $oMfaService);

            } elseif ($oInput::post('action') === 'setup_cancel') {

                $this->cancelChallenge(
                    $oToken,
                    $oMfaService,
                    $oTokenModel,
                    $oUserFeedback,
                    'Two-factor authentication setup was cancelled. Please sign in to try again.'
                );

            } elseif ($oInput::post('action') === 'cancel') {

                $this->cancelChallenge(
                    $oToken,
                    $oMfaService,
                    $oTokenModel,
                    $oUserFeedback,
                    'Sign in was cancelled. Please try again.'
                );

            } elseif ($oInput::post('action') === 'switch') {

                $sSlug = (string) $oInput::post('driver');
                $this->log('User is switching MFA method to ' . $sSlug);

                $oSwitched = null;
                foreach ($oMfaService->getAuthenticationMethods($oUser) as $oCandidate) {
                    if ($oCandidate->getSlug() === $sSlug) {
                        $oSwitched = $oCandidate;
                        break;
                    }
                }

                if (!$oSwitched) {
                    $oUserFeedback->error('That verification method is not available.');
                    $oDriver = $oMfaService->selectDriver($oUser, $oToken);
                    if ($oDriver) {
                        $this->renderForm($oDriver, $oToken, $oMfaService);
                    } else {
                        $this->renderSetup($oToken, $oMfaService);
                    }
                    return;
                }

                /**
                 * Switching lands on a method the user has already enrolled, so any
                 * setup they were part way through is abandoned here; leaving it on
                 * the token would send them straight back to it on the next render.
                 */
                $oMfaService->clearPendingSetup($oToken);
                $oToken->setData((object) [
                    $oMfaService::TOKEN_DATA_KEY_DRIVER   => $oSwitched->getSlug(),
                    $oMfaService::TOKEN_DATA_KEY_IS_SETUP => false,
                ]);
                $oSwitched->preForm($oToken, $oUserFeedback);
                $this->renderForm($oSwitched, $oToken, $oMfaService);
                $oSwitched->postForm($oToken);

            } elseif ($oInput::post('action') === 'setup_choose') {

                $this->handleSetupChoose($oToken, $oMfaService, $oUserFeedback);

            } elseif ($oInput::post('action') === 'setup_confirm') {

                $this->handleSetupConfirm($oToken, $oMfaService, $oUserFeedback, $oInput);

            } else {

                if ($oMfaService->userNeedsSetup($oUser) || $oMfaService->getPendingSetup($oToken)) {
                    if ($oMfaService->getPendingSetup($oToken)) {
                        $sSlug   = (string) $oToken->getData($oMfaService::TOKEN_DATA_KEY_DRIVER);
                        $oDriver = $oMfaService->getDriverBySlug($sSlug);
                        $this->renderSetupConfirm($oDriver, $oToken, $oMfaService);
                    } else {
                        $this->renderSetup($oToken, $oMfaService);
                    }
                    return;
                }

                $oDriver = $oMfaService->selectDriver($oUser, $oToken);
                if (!$oDriver) {
                    $this->renderSetup($oToken, $oMfaService);
                    return;
                }

                $oDriver->preForm($oToken, $oUserFeedback);
                $this->renderForm($oDriver, $oToken, $oMfaService);
                $oDriver->postForm($oToken);
            }

        } catch (Exception\TokenException\IsExpiredException $e) {
            $this->log(sprintf(
                'Caught exception: [%s] %s',
                $e::class,
                $e->getMessage()
            ));
            $sReturnTo = $this->challengeReturnTo($e->getToken(), $oMfaService);
            $oTokenModel->delete($e->getToken()->id);
            $oMfaService->clearTokenCookie();
            $oUserFeedback->info('Your session expired, please try again.');
            redirect(loginUrl($sReturnTo));

        } catch (DecodeException|Exception\TokenException $e) {
            $this->log(sprintf(
                'Caught exception: [%s] %s',
                $e::class,
                $e->getMessage()
            ));

            $sReturnTo = $e instanceof Exception\TokenException
                ? $this->challengeReturnTo($e->getToken(), $oMfaService)
                : null;

            if ($e instanceof Exception\TokenException && $e->getToken()) {
                $oTokenModel->delete($e->getToken()->id);
            }

            $oMfaService->clearTokenCookie();
            $oUserFeedback->error(
                $e instanceof Exception\TokenException\MissingCookieException ||
                $e instanceof Exception\TokenException\TooManyAttemptsException
                    ? $e->getMessage()
                    : 'We could not continue your sign-in. Please sign in and try again.'
            );
            redirect(loginUrl($sReturnTo));

        } catch (Throwable $e) {
            $this->log(sprintf(
                'Caught exception: [%s] %s',
                $e::class,
                $e->getMessage()
            ));
            show404();
        }
    }

    // --------------------------------------------------------------------------

    public function manage(): void
    {
        if (!isLoggedIn()) {
            unauthorised('Please log in to manage your verification methods.');
        }

        /** @var MultiFactorAuth $oMfaService */
        $oMfaService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Service\Input $oInput */
        $oInput = Factory::service('Input');
        /** @var Service\UserFeedback $oUserFeedback */
        $oUserFeedback = Factory::service('UserFeedback');
        /** @var Service\Session $oSession */
        $oSession = Factory::service('Session');
        /** @var Service\View $oView */
        $oView = Factory::service('View');

        $oUser      = activeUser();
        $sReturnUrl = $this->sanitiseReturnUrl(
            (string) ($oInput::post('return') ?: $oInput::get('return'))
        );

        if (!$oMfaService->userCanManageMethods($oUser)) {
            show404();
        }

        $oPending = $oSession->getUserData(static::SESSION_PENDING_SETUP);

        try {

            if ($oInput::post('action') === 'set_default') {
                $oMfaService->setDefaultMethod($oUser, (string) $oInput::post('driver'));
                $oUserFeedback->success('Default verification method updated.');
                redirect($this->manageUrl($sReturnUrl));

            } elseif ($oInput::post('action') === 'remove') {
                $oMfaService->removeMethod($oUser, (string) $oInput::post('driver'));
                $oUserFeedback->success('Verification method removed.');
                redirect($this->manageUrl($sReturnUrl));

            } elseif ($oInput::post('action') === 'setup_choose') {
                $sSlug   = (string) $oInput::post('driver');
                $oDriver = $this->findSetupDriver($oMfaService, $oUser, $sSlug);
                if ($oDriver->requiresEnrollment()) {
                    $oStart = $oDriver->setupStart($oUser);
                    $oSession->setUserData(static::SESSION_PENDING_SETUP, (object) [
                        'driver'  => $sSlug,
                        'pending' => $oStart,
                    ]);
                    $oPending = $oSession->getUserData(static::SESSION_PENDING_SETUP);
                } else {
                    $oMfaService->enrollMethod(
                        $oUser,
                        $sSlug,
                        $oDriver->setupComplete($oUser, '', (object) []),
                        empty($oMfaService->getUserMethods($oUser))
                    );
                    $oUserFeedback->success($oDriver->getLabel() . ' has been added to your account.');
                    redirect($this->manageUrl($sReturnUrl));
                }

            } elseif ($oInput::post('action') === 'setup_confirm' && $oPending) {
                $oDriver = $oMfaService->getDriverBySlug($oPending->driver);
                    $oData   = $oDriver->setupComplete(
                    $oUser,
                    (string) $oInput::post('code'),
                    (object) $oPending->pending
                );
                $oMfaService->enrollMethod(
                    $oUser,
                    $oPending->driver,
                    $oData,
                    empty($oMfaService->getUserMethods($oUser))
                );
                $oSession->unsetUserData(static::SESSION_PENDING_SETUP);
                $oUserFeedback->success($oDriver->getLabel() . ' has been added to your account.');
                redirect($this->manageUrl($sReturnUrl));

            } elseif ($oInput::post('action') === 'setup_cancel') {
                $oSession->unsetUserData(static::SESSION_PENDING_SETUP);
                $oPending = null;
            }

        } catch (Exception\InvalidCodeException $e) {
            $oUserFeedback->error($e->getMessage());

        } catch (Exception\MfaException $e) {
            $oUserFeedback->error($e->getMessage());
        }

        $this->data['oUser']         = $oUser;
        $this->data['sGroupMode']    = $oMfaService->getGroupMode($oUser);
        $this->data['aMethods']      = $oMfaService->getUserMethods($oUser);
        $this->data['aSetupDrivers'] = $oMfaService->getSetupDrivers($oUser);
        $this->data['oPending']      = is_object($oPending) ? $oPending : null;
        $this->data['aCanRemove']    = [];
        $this->data['aDriverLabels'] = [];
        $this->data['sReturnUrl']     = $sReturnUrl;

        //  Resolve the driver behind an in-progress setup so a FormFragment
        //  driver can render its own confirm panel (and have its assets loaded).
        $oPendingDriver = null;
        if (is_object($oPending) && !empty($oPending->driver)) {
            try {
                $oPendingDriver = $oMfaService->getDriverBySlug((string) $oPending->driver);
            } catch (NailsException $e) {
                $oPendingDriver = null;
            }
        }
        $this->data['oPendingDriver'] = $oPendingDriver;

        foreach ($this->data['aMethods'] as $oMethod) {
            $sDriver = (string) $oMethod->driver;

            $this->data['aCanRemove'][$sDriver] = $oMfaService->userCanRemoveMethod($oUser, $sDriver);
        }

        try {
            foreach ($oMfaService->getEnabledDrivers() as $oDriver) {
                $this->data['aDriverLabels'][$oDriver->getSlug()] = $oDriver->getLabel();
            }
        } catch (Exception\MfaException $e) {
            $this->data['aDriverLabels'] = [];
        }

        $this->oMetaData->setTitles(['Security', 'Two-factor authentication']);

        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/manage.php');
        $this->loadDriverAssets($oPendingDriver);

        $oView
            ->load([
                'mfa/structure/header',
                'mfa/manage',
                'mfa/structure/footer',
            ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    private function handleSetupChoose(
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService,
        Service\UserFeedback $oUserFeedback
    ): void {
        /** @var Service\Input $oInput */
        $oInput  = Factory::service('Input');
        $sSlug   = (string) $oInput::post('driver');
        $oUser   = $oToken->user();
        $oDriver = $this->findSetupDriver($oMfaService, $oUser, $sSlug);

        $this->log('User chose MFA setup driver ' . $sSlug);

        $this->beginSetup($oDriver, $oToken, $oMfaService, $oUserFeedback);
    }

    // --------------------------------------------------------------------------

    /**
     * Starts setup of a chosen driver, either by collecting whatever it needs to
     * enroll the user or, for drivers with nothing to enroll, by challenging them
     * with it straight away.
     *
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    private function beginSetup(
        Interfaces\Authentication\Driver $oDriver,
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService,
        Service\UserFeedback $oUserFeedback
    ): void {
        $sSlug = (string) $oDriver->getSlug();

        $oToken->setData((object) [
            $oMfaService::TOKEN_DATA_KEY_DRIVER   => $sSlug,
            $oMfaService::TOKEN_DATA_KEY_IS_SETUP => true,
        ]);

        if ($oDriver->requiresEnrollment()) {
            $oPending = $oDriver->setupStart($oToken->user());
            $oMfaService->setPendingSetup($oToken, $sSlug, $oPending);
            $this->renderSetupConfirm($oDriver, $oToken, $oMfaService);
            return;
        }

        $oDriver->preForm($oToken, $oUserFeedback);
        $this->renderForm($oDriver, $oToken, $oMfaService);
        $oDriver->postForm($oToken);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    private function handleSetupConfirm(
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService,
        Service\UserFeedback $oUserFeedback,
        Service\Input $oInput
    ): void {
        $oPending = $oMfaService->getPendingSetup($oToken);
        $sSlug    = (string) $oToken->getData($oMfaService::TOKEN_DATA_KEY_DRIVER);

        if (!$oPending || $sSlug === '') {
            $oUserFeedback->error('Your setup session expired. Please try again.');
            $this->renderSetup($oToken, $oMfaService);
            return;
        }

        $oDriver = $oMfaService->getDriverBySlug($sSlug);

        try {
            $oMfaService->registerFailedAttempt($oToken);
            $oData = $oDriver->setupComplete(
                $oToken->user(),
                (string) $oInput::post('code'),
                $oPending
            );
            $oMfaService->enrollMethod($oToken->user(), $sSlug, $oData, true);
            $oMfaService->clearPendingSetup($oToken);

            $sRedirectUrl = $oMfaService->completeChallenge(
                $oToken,
                (bool) $oInput::post('remember')
            );

            $this->log('User completed MFA setup and signed in');
            redirect($sRedirectUrl);

        } catch (Exception\InvalidCodeException $e) {
            $oUserFeedback->error($e->getMessage());
            $this->renderSetupConfirm($oDriver, $oToken, $oMfaService);
        }
    }

    // --------------------------------------------------------------------------

    /**
     * @throws Exception\MfaException
     */
    private function findSetupDriver(
        MultiFactorAuth $oMfaService,
        \Nails\Auth\Resource\User $oUser,
        string $sSlug
    ): Interfaces\Authentication\Driver {
        foreach ($oMfaService->getSetupDrivers($oUser) as $oDriver) {
            if ($oDriver->getSlug() === $sSlug) {
                return $oDriver;
            }
        }

        throw new Exception\MfaException('That verification method is not available.');
    }

    // --------------------------------------------------------------------------

    /**
     * Restricts the optional return URL to this site
     */
    private function sanitiseReturnUrl(string $sUrl): ?string
    {
        $sUrl = trim($sUrl);

        if ($sUrl === '' || str_starts_with($sUrl, '//') || preg_match('/[\x00-\x1F\x7F]/', $sUrl)) {
            return null;
        }

        $aUrl = parse_url($sUrl);
        if ($aUrl === false) {
            return null;
        }

        if (empty($aUrl['host'])) {
            return empty($aUrl['scheme'])
                ? siteUrl(ltrim($sUrl, '/'))
                : null;
        }

        $aBaseUrl = parse_url((string) Config::get('BASE_URL'));
        $sScheme  = strtolower((string) ($aUrl['scheme'] ?? ''));

        if (
            !in_array($sScheme, ['http', 'https'], true)
            || strtolower((string) $aUrl['host']) !== strtolower((string) ($aBaseUrl['host'] ?? ''))
            || ($aUrl['port'] ?? null) !== ($aBaseUrl['port'] ?? null)
        ) {
            return null;
        }

        return $sUrl;
    }

    // --------------------------------------------------------------------------

    /**
     * Builds the management URL while preserving its optional return destination
     */
    private function manageUrl(?string $sReturnUrl): string
    {
        return 'mfa/manage' . ($sReturnUrl ? '?return=' . rawurlencode($sReturnUrl) : '');
    }

    // --------------------------------------------------------------------------

    /**
     * Recovers the destination captured when MFA interrupted the login.
     */
    private function challengeReturnTo(
        ?Resource\Token $oToken,
        MultiFactorAuth $oMfaService
    ): ?string {
        if (!$oToken) {
            return null;
        }

        $sReturnTo = $oToken->getData($oMfaService::TOKEN_DATA_KEY_RETURN_TO);

        return is_string($sReturnTo) && $sReturnTo !== ''
            ? $sReturnTo
            : null;
    }

    // --------------------------------------------------------------------------

    /**
     * Abandons the challenge: the token is spent so a cancelled attempt cannot be
     * resumed, and the user is returned to the login page to start again.
     */
    private function cancelChallenge(
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService,
        Model\Token $oTokenModel,
        Service\UserFeedback $oUserFeedback,
        string $sMessage
    ): void {
        $this->log('User cancelled the MFA challenge');

        $sReturnTo = $this->challengeReturnTo($oToken, $oMfaService);

        if ($oToken->id) {
            $oTokenModel->delete($oToken->id);
        }

        $oMfaService->clearTokenCookie();
        $oUserFeedback->info($sMessage);
        redirect(loginUrl($sReturnTo));
    }

    // --------------------------------------------------------------------------

    /**
     * The methods the user could verify with instead of the one in front of them.
     *
     * Enrollment, not the driver, decides this: any method the user has already
     * set up is a way past a challenge they cannot complete, whether they are
     * stuck on a code which never arrived or a passkey prompt their device will
     * not answer.
     *
     * @param Interfaces\Authentication\Driver|null $oDriver The method in play, excluded from the result
     *
     * @return Interfaces\Authentication\Driver[]
     * @throws NailsException
     */
    private function otherMethods(
        MultiFactorAuth $oMfaService,
        Resource\Token $oToken,
        ?Interfaces\Authentication\Driver $oDriver
    ): array {
        $oUser = $oToken->user();
        if ($oUser === null) {
            return [];
        }

        $sSlug = $oDriver ? (string) $oDriver->getSlug() : null;

        return array_values(array_filter(
            $oMfaService->getAuthenticationMethods($oUser),
            fn(Interfaces\Authentication\Driver $oOther): bool => $oOther->getSlug() !== $sSlug
        ));
    }

    // --------------------------------------------------------------------------

    /**
     * Describes the trusted device window in the units the configured TTL divides into
     */
    private function trustedForLabel(MultiFactorAuth $oMfaService): string
    {
        $iTtl = $oMfaService->getTrustedDeviceTtl();

        foreach ([86400 => 'day', 3600 => 'hour', 60 => 'minute'] as $iSeconds => $sUnit) {
            if ($iTtl >= $iSeconds) {
                $iValue = (int) round($iTtl / $iSeconds);
                return sprintf('%d %s', $iValue, $iValue === 1 ? $sUnit : $sUnit . 's');
            }
        }

        return sprintf('%d seconds', $iTtl);
    }

    // --------------------------------------------------------------------------

    private function log(string $sMessage): void
    {
        $this->oLogger->info(sprintf(
            '[%s] %s',
            static::class,
            $sMessage
        ));
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ViewNotFoundException
     * @throws \Exception
     */
    private function renderForm(
        Interfaces\Authentication\Driver $oDriver,
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService
    ): void {
        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/form.php');
        $this->loadDriverAssets($oDriver);

        $bIsSetup = (bool) $oToken->getData($oMfaService::TOKEN_DATA_KEY_IS_SETUP);
        $iSetup   = count($oMfaService->getSetupDrivers($oToken->user()));

        /** @var Service\View $oView */
        $oView = Factory::service('View');
        $oView
            ->setData([
                'oDriver'       => $oDriver,
                'oToken'        => $oToken,
                'aOtherMethods' => $this->otherMethods($oMfaService, $oToken, $oDriver),
                'bIsSetup'      => $bIsSetup,
                /**
                 * During setup the chooser this returns to lists these same drivers,
                 * so going back to a list of one is no choice at all. During a
                 * challenge it is the user's only way past a method which will not
                 * let them in, so a single option is still worth offering.
                 */
                'bCanChooseAnother' => $bIsSetup ? $iSetup > 1 : $iSetup > 0,
                'sTrustedForLabel'  => $this->trustedForLabel($oMfaService),
            ])
            ->load([
                'mfa/structure/header',
                'mfa/form',
                'mfa/structure/footer',
            ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ViewNotFoundException
     */
    private function renderSetup(Resource\Token $oToken, MultiFactorAuth $oMfaService): void
    {
        $aDrivers = $oMfaService->getSetupDrivers($oToken->user());

        //  A choice of one is no choice at all
        if (count($aDrivers) === 1) {

            $oDriver = reset($aDrivers);

            $this->log(sprintf(
                'Only one MFA setup method is available, choosing %s',
                $oDriver->getSlug()
            ));

            /** @var Service\UserFeedback $oUserFeedback */
            $oUserFeedback = Factory::service('UserFeedback');

            $this->beginSetup($oDriver, $oToken, $oMfaService, $oUserFeedback);
            return;
        }

        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/setup.php');

        /** @var Service\View $oView */
        $oView = Factory::service('View');
        $oView
            ->setData([
                'oToken'            => $oToken,
                'aDrivers'          => $aDrivers,
                'aOtherMethods'     => $this->otherMethods($oMfaService, $oToken, null),
                //  The drivers to set up are listed above, so there is no need to offer them again
                'bCanChooseAnother' => false,
                'bIsSetup'          => true,
            ])
            ->load([
                'mfa/structure/header',
                'mfa/setup',
                'mfa/structure/footer',
            ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ViewNotFoundException
     */
    private function renderSetupConfirm(
        Interfaces\Authentication\Driver $oDriver,
        Resource\Token $oToken,
        MultiFactorAuth $oMfaService
    ): void {
        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/setup_confirm.php');
        $this->loadDriverAssets($oDriver);

        /** @var Service\View $oView */
        $oView = Factory::service('View');
        $oView
            ->setData([
                'oDriver'           => $oDriver,
                'oToken'            => $oToken,
                'oPending'          => $oMfaService->getPendingSetup($oToken),
                'aOtherMethods'     => $this->otherMethods($oMfaService, $oToken, $oDriver),
                'bCanChooseAnother' => count($oMfaService->getSetupDrivers($oToken->user())) > 1,
                'bIsSetup'          => true,
                'sTrustedForLabel'  => $this->trustedForLabel($oMfaService),
            ])
            ->load([
                'mfa/structure/header',
                'mfa/setup_confirm',
                'mfa/structure/footer',
            ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws AssetException
     */
    protected function loadStyles($sView): void
    {
        if (!is_file($sView)) {
            /** @var Service\Asset $oAsset */
            $oAsset = Factory::service('Asset');
            $oAsset
                ->clear()
                ->load('nails.min.css', \Nails\Common\Constants::MODULE_SLUG)
                //  Sizes the .nails-auth wrapper these views share with the auth pages
                ->load('styles.min.css', Auth\Constants::MODULE_SLUG);
        }
    }

    // --------------------------------------------------------------------------

    /**
     * Loads a FormFragment driver's front-end assets.
     *
     * Called immediately after loadStyles() so it runs after that method's
     * clear(). Unlike loadStyles() it fires even when the app has overridden the
     * view: a FormFragment driver's assets are functional, not cosmetic.
     *
     * @throws FactoryException
     */
    protected function loadDriverAssets(?Interfaces\Authentication\Driver $oDriver): void
    {
        if ($oDriver instanceof Interfaces\Authentication\Driver\FormFragment) {
            $oDriver->loadAssets();
        }
    }
}
