<?php

namespace Nails\MFA\Auth\Admin\User\Tab;

use Nails\Auth\Interfaces\Admin\User\Tab;
use Nails\Auth\Resource\User;
use Nails\Common\Service\Input;
use Nails\Common\Service\View;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Model\GroupPolicy;
use Nails\MFA\Service\Logger;
use Nails\MFA\Service\MultiFactorAuth;

class Mfa implements Tab
{
    public function getLabel(): string
    {
        return 'MFA';
    }

    // --------------------------------------------------------------------------

    public static function isEnabled(User $user): bool
    {
        return (int) $user->id === (int) activeUser('id') || userHasPermission('admin:auth:accounts:edit');
    }

    // --------------------------------------------------------------------------

    public function getOrder(): ?float
    {
        return 3.5;
    }

    // --------------------------------------------------------------------------

    public function getBody(User $oUser): string
    {
        /** @var View $oView */
        $oView = Factory::service('View');
        /** @var MultiFactorAuth $oMfa */
        $oMfa = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Input $oInput */
        $oInput = Factory::service('Input');

        $aDriverLabels = [];
        try {
            foreach ($oMfa->getEnabledDrivers() as $oDriver) {
                $aDriverLabels[$oDriver->getSlug()] = $oDriver->getLabel();
            }
        } catch (MfaException $e) {
            $aDriverLabels = [];
        }

        $bIsSelf = (int) $oUser->id === (int) activeUser('id');

        return $oView->load(
            ['User/tabs/mfa'],
            [
                'oUser'          => $oUser,
                'sGroupMode'     => $oMfa->getGroupMode($oUser),
                'aModes'         => GroupPolicy::modes(),
                'aMethods'       => $oMfa->getUserMethods($oUser),
                'aDriverLabels'  => $aDriverLabels,
                'bIsSelf'        => $bIsSelf,
                'sManageUrl'     => $bIsSelf && $oMfa->userCanManageMethods($oUser)
                    ? siteUrl('mfa/manage')
                        . '?return='
                        . rawurlencode((string) $oInput->server('REQUEST_URI'))
                    : null,
            ],
            true
        );
    }

    // --------------------------------------------------------------------------

    public function getAdditionalMarkup(User $oUser): string
    {
        return '';
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    public function getValidationRules(User $oUser): array
    {
        return [];
    }

    // --------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $aPost
     *
     * @return array<string, mixed>
     */
    public function getPostData(User $oUser, array $aPost): array
    {
        /** @var MultiFactorAuth $oMfa */
        $oMfa = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        /** @var Logger $oLogger */
        $oLogger = Factory::service('Logger', Constants::MODULE_SLUG);

        $sDefault = $aPost['mfa_default_driver'] ?? '';
        if (is_string($sDefault) && $sDefault !== '' && $oMfa->getUserMethod($oUser, $sDefault)) {
            $oMfa->setDefaultMethod($oUser, $sDefault);
        }

        $aResets = array_filter((array) ($aPost['mfa_reset_driver'] ?? []));
        foreach ($aResets as $sDriver) {
            $oMfa->removeMethod($oUser, (string) $sDriver, true);
            $oLogger->info(sprintf(
                'Admin reset MFA method %s for user %s',
                $sDriver,
                $oUser->id
            ));
        }

        return [];
    }
}
