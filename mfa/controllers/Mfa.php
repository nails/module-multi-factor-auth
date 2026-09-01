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
    private Logger $oLogger;

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function __construct()
    {
        parent::__construct();
        $this->oLogger = Factory::service('Logger', Constants::MODULE_SLUG);
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
        /** @var Service\Uri $oUri */
        $oUri = Factory::service('Uri');
        /** @var Service\Input $oInput */
        $oInput = Factory::service('Input');
        /** @var Service\UserFeedback $oUserFeedback */
        $oUserFeedback = Factory::service('UserFeedback');
        /** @var MultiFactorAuth $oMfaService */
        $oMfaService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Auth\Service\Authentication $oAuthenticationService */
        $oAuthenticationService = Factory::service('Authentication', Auth\Constants::MODULE_SLUG);
        /** @var Auth\Model\User $oUserModel */
        $oUserModel = Factory::model('User', Auth\Constants::MODULE_SLUG);

        // --------------------------------------------------------------------------

        try {

            if (isLoggedIn()) {
                throw new Exception\TokenException('User is already logged in');
            }

            $oToken = $oMfaService->getToken(
                (string) $oUri->segment(
                    $oMfaService::MFA_URL_TOKEN_SEGMENT
                ),
                $oInput::ipAddress()
            );

            $oDriver = $this->selectDriver(
                $oMfaService->getAuthenticationMethods(
                    $oToken->user()
                )
            );

            if ($oInput::post('action') === 'verify') {

                $this->log('User is attempting to verify');

                try {

                    $oDriver->validate($oToken, $oInput::post('code'));
                    $oMfaService->setIsPrivileged($oToken->user(), (bool) $oInput::post('remember'));
                    $oTokenModel->delete($oToken->id);
                    $oAuthenticationService->login($oToken->user());

                    if ($oToken->getData($oMfaService::TOKEN_DATA_KEY_IS_REMEMBERED)) {
                        $oUserModel->setRememberCookie(
                            $oToken->user()->id,
                            $oToken->user()->password,
                            $oToken->user()->email
                        );
                    }

                    $sRedirectUrl = $oToken->getData(
                        $oMfaService::TOKEN_DATA_KEY_RETURN_TO
                    );

                    $this->log(sprintf(
                        'User verified successfully, redirecting to "%s"',
                        $sRedirectUrl ?? siteUrl()
                    ));

                    redirect(
                        $sRedirectUrl
                    );

                } catch (Exception\InvalidCodeException $e) {
                    $this->log(sprintf(
                        'Caught exception: [%s] %s',
                        $e::class,
                        $e->getMessage()
                    ));
                    $oUserFeedback->error($e->getMessage());
                    $this->renderForm($oDriver, $oToken);
                }

            } elseif ($oInput::post('action') === 'restart') {
                $this->log('User is restarting authentication');
                $oTokenModel->delete($oToken->id);
                $oMfaService->authenticate(
                    $oToken->user(),
                    $oToken->getData($oMfaService::TOKEN_DATA_KEY_IS_REMEMBERED),
                    true
                );

            } else {

                $oDriver->preForm($oToken, $oUserFeedback);
                $this->renderForm($oDriver, $oToken);
                $oDriver->postForm($oToken);
            }

        } catch (Exception\TokenException\IsExpiredException $e) {
            //  Generate a new token to stay in the loop
            $this->log(sprintf(
                'Caught exception: [%s] %s',
                $e::class,
                $e->getMessage()
            ));
            $oUserFeedback->info('Your session expired, please try again.');
            $oMfaService->authenticate(
                $e->getToken()->user(),
                $e->getToken()->getData($oMfaService::TOKEN_DATA_KEY_IS_REMEMBERED),
                true
            );

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

    private function log(string $sMessage): void
    {
        $this->oLogger->info(sprintf(
            '[%s] %s',
            static::class,
            $sMessage
        ));
    }

    // --------------------------------------------------------------------------

    private function selectDriver(array $aDrivers): Interfaces\Authentication\Driver
    {
        //  @todo (Pablo 2023-02-22) - choose the appropriate driver for the user (e.g. email, app, etc)
        return reset($aDrivers);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ViewNotFoundException
     * @throws \Exception
     */
    private function renderForm(Interfaces\Authentication\Driver $oDriver, Resource\Token $oToken): void
    {
        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/form.php');

        /** @var Service\View $oView */
        $oView = Factory::service('View');
        $oView
            ->setData([
                'oDriver' => $oDriver,
                'oToken'  => $oToken,
            ])
            ->load([
                'structure/header/blank',
                'mfa/form',
                'structure/footer/blank',
            ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws AssetException
     */
    protected function loadStyles($sView): void
    {
        //  Test if a view has been provided by the app
        if (!is_file($sView)) {
            /** @var Service\Asset $oAsset */
            $oAsset = Factory::service('Asset');
            $oAsset
                ->clear()
                ->load('nails.min.css', \Nails\Common\Constants::MODULE_SLUG);
        }
    }
}
