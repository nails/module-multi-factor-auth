<?php

use Nails\MFA\Constants;
use Nails\MFA\Service\MultiFactorAuth;
use Nails\Config;
use Nails\Factory;
use Nails\MFA\Exception;

class Mfa extends \App\Controller\Base
{
    public function index()
    {
        /** @var \Nails\Common\Service\Uri $oUri */
        $oUri = Factory::service('Uri');
        /** @var \Nails\Common\Service\Input $oInput */
        $oInput = Factory::service('Input');
        /** @var \Nails\Common\Service\UserFeedback $oUserFeedback */
        $oUserFeedback = Factory::service('UserFeedback');
        /** @var MultiFactorAuth $oMfaService */
        $oMfaService = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var \Nails\MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var \Nails\Auth\Service\Authentication $oAuthenticationService */
        $oAuthenticationService = Factory::service('Authentication', \Nails\Auth\Constants::MODULE_SLUG);
        /** @var \Nails\Auth\Model\User $oUserModel */
        $oUserModel = Factory::model('User', \Nails\Auth\Constants::MODULE_SLUG);

        // --------------------------------------------------------------------------

        try {

            if (isLoggedIn()) {
                throw new Exception\TokenException('User is already logged in');
            }

            $oToken = $oMfaService->getToken(
                $oUri->segment(
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

                    redirect(
                        $oToken->getData(
                            $oMfaService::TOKEN_DATA_KEY_RETURN_TO
                        )
                    );

                } catch (\Nails\MFA\Exception\InvalidCodeException $e) {
                    $oUserFeedback->error($e->getMessage());
                    $this->renderForm($oDriver, $oToken);
                }

            } elseif ($oInput::post('action') === 'restart') {
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
            $oUserFeedback->info('Your session expired, please try again.');
            $oMfaService->authenticate(
                $e->getToken()->user(),
                $e->getToken()->getData($oMfaService::TOKEN_DATA_KEY_IS_REMEMBERED),
                true
            );

        } catch (Exception\TokenException $e) {
            show404();
        }
    }

    // --------------------------------------------------------------------------

    private function selectDriver(array $aDrivers): \Nails\MFA\Interfaces\Authentication\Driver
    {
        //  @todo (Pablo 2023-02-22) - choose the appropriate driver for the user (e.g. email, app, etc)
        return reset($aDrivers);
    }

    // --------------------------------------------------------------------------

    private function renderForm(\Nails\MFA\Interfaces\Authentication\Driver $oDriver, \Nails\MFA\Resource\Token $oToken): void
    {
        $this->loadStyles(Config::get('NAILS_APP_PATH') . 'application/modules/mfa/views/form.php');

        /** @var \Nails\Common\Service\View $oView */
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

    protected function loadStyles($sView)
    {
        //  Test if a view has been provided by the app
        if (!is_file($sView)) {
            /** @var \Nails\Common\Service\Asset $oAsset */
            $oAsset = Factory::service('Asset');
            $oAsset
                ->clear()
                ->load('nails.min.css', \Nails\Common\Constants::MODULE_SLUG);
        }
    }
}
