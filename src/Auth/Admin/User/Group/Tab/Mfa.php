<?php

namespace Nails\MFA\Auth\Admin\User\Group\Tab;

use Nails\Auth\Admin\Permission;
use Nails\Auth\Interfaces\Admin\User\Group\Tab;
use Nails\Auth\Resource\User\Group;
use Nails\Common\Exception\ValidationException;
use Nails\Common\Service\View;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Model\GroupPolicy;
use Nails\MFA\Service\Logger;

class Mfa implements Tab
{
    public function getLabel(): string
    {
        return 'MFA';
    }

    // --------------------------------------------------------------------------

    public static function isEnabled(?Group $oGroup): bool
    {
        return $oGroup !== null && userHasPermission(Permission\Groups\Edit::class);
    }

    // --------------------------------------------------------------------------

    public function getOrder(): ?float
    {
        return 1.5;
    }

    // --------------------------------------------------------------------------

    public function getBody(?Group $oGroup): string
    {
        if (!$oGroup) {
            return '';
        }

        /** @var View $oView */
        $oView = Factory::service('View');
        /** @var GroupPolicy $oPolicyModel */
        $oPolicyModel = Factory::model('GroupPolicy', Constants::MODULE_SLUG);

        return $oView->load(
            ['User/Group/tabs/mfa'],
            [
                'oGroup'      => $oGroup,
                'aModes'      => GroupPolicy::modes(),
                'sPolicyMode' => $oPolicyModel->getModeForGroup((int) $oGroup->id),
            ],
            true
        );
    }

    // --------------------------------------------------------------------------

    public function getAdditionalMarkup(?Group $oGroup): string
    {
        return '';
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    public function getValidationRules(?Group $oGroup): array
    {
        return [
            'mfa_group_policy' => [
                static function ($sMode): void {
                    if (!array_key_exists((string) $sMode, GroupPolicy::modes())) {
                        throw new ValidationException('Select a valid MFA group policy.');
                    }
                },
            ],
        ];
    }

    // --------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $aPost
     *
     * @return array<string, mixed>
     */
    public function getPostData(?Group $oGroup, array $aPost): array
    {
        return [];
    }

    // --------------------------------------------------------------------------

    /**
     * @param array<string, mixed> $aPost
     */
    public function afterSave(Group $oGroup, array $aPost): void
    {
        $sMode = (string) ($aPost['mfa_group_policy'] ?? '');
        if (!array_key_exists($sMode, GroupPolicy::modes())) {
            return;
        }

        /** @var GroupPolicy $oPolicyModel */
        $oPolicyModel = Factory::model('GroupPolicy', Constants::MODULE_SLUG);
        $oPolicyModel->setModeForGroup((int) $oGroup->id, $sMode);

        /** @var Logger $oLogger */
        $oLogger = Factory::service('Logger', Constants::MODULE_SLUG);
        $oLogger->info(sprintf(
            'Updated MFA policy for group %s to %s',
            $oGroup->id,
            $sMode
        ));
    }
}
