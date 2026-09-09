<?php

namespace Nails\MFA\Model;

use Nails\Auth;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Exception\ModelException;
use Nails\Common\Helper\Model\Where;
use Nails\Common\Model\Base;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Resource;

class GroupPolicy extends Base
{
    const TABLE             = NAILS_DB_PREFIX . 'mfa_group_policy';
    const RESOURCE_NAME     = 'GroupPolicy';
    const RESOURCE_PROVIDER = Constants::MODULE_SLUG;

    const MODE_DISABLED = 'DISABLED';
    const MODE_OPTIONAL = 'OPTIONAL';
    const MODE_REQUIRED = 'REQUIRED';

    // --------------------------------------------------------------------------

    public function __construct()
    {
        parent::__construct();
        $this
            ->hasOne('group', 'UserGroup', Auth\Constants::MODULE_SLUG);
    }

    // --------------------------------------------------------------------------

    /**
     * @return string[]
     */
    public static function modes(): array
    {
        return [
            static::MODE_DISABLED => 'Disabled',
            static::MODE_OPTIONAL => 'Optional',
            static::MODE_REQUIRED => 'Required',
        ];
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getByGroupId(int $iGroupId): ?Resource\GroupPolicy
    {
        /** @var Resource\GroupPolicy|null $oPolicy */
        $oPolicy = $this->getAll([
            new Where('group_id', $iGroupId),
        ])[0] ?? null;

        return $oPolicy;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getModeForGroup(int $iGroupId): string
    {
        $oPolicy = $this->getByGroupId($iGroupId);

        return $oPolicy->mode ?? static::MODE_DISABLED;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function setModeForGroup(int $iGroupId, string $sMode): Resource\GroupPolicy
    {
        if (!array_key_exists($sMode, static::modes())) {
            throw new ModelException('Invalid MFA group policy mode: ' . $sMode);
        }

        $oPolicy = $this->getByGroupId($iGroupId);

        if ($oPolicy) {
            $this->update($oPolicy->id, ['mode' => $sMode]);
            /** @var Resource\GroupPolicy $oUpdated */
            $oUpdated = $this->getById($oPolicy->id);
            return $oUpdated;
        }

        /** @var Resource\GroupPolicy $oCreated */
        $oCreated = $this->create([
            'group_id' => $iGroupId,
            'mode'     => $sMode,
        ], true);

        return $oCreated;
    }
}
