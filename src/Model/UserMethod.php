<?php

namespace Nails\MFA\Model;

use Nails\Auth;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Exception\ModelException;
use Nails\Common\Helper\Model\Where;
use Nails\Common\Model\Base;
use Nails\Common\Service\Database;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Resource;

class UserMethod extends Base
{
    const TABLE             = NAILS_DB_PREFIX . 'mfa_user_method';
    const RESOURCE_NAME     = 'UserMethod';
    const RESOURCE_PROVIDER = Constants::MODULE_SLUG;

    // --------------------------------------------------------------------------

    public function __construct()
    {
        parent::__construct();
        $this
            ->hasOne('user', 'User', Auth\Constants::MODULE_SLUG);
    }

    // --------------------------------------------------------------------------

    /**
     * @return Resource\UserMethod[]
     * @throws FactoryException
     * @throws ModelException
     */
    public function getByUserId(int $iUserId): array
    {
        /** @var Resource\UserMethod[] $aMethods */
        $aMethods = $this->getAll([
            new Where('user_id', $iUserId),
        ]);

        return $aMethods;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getByUserAndDriver(int $iUserId, string $sDriver): ?Resource\UserMethod
    {
        /** @var Resource\UserMethod|null $oMethod */
        $oMethod = $this->getAll([
            new Where('user_id', $iUserId),
            new Where('driver', $sDriver),
        ])[0] ?? null;

        return $oMethod;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getDefaultForUser(int $iUserId): ?Resource\UserMethod
    {
        $aMethods = $this->getByUserId($iUserId);

        foreach ($aMethods as $oMethod) {
            if ($oMethod->is_default) {
                return $oMethod;
            }
        }

        return $aMethods[0] ?? null;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function setDefault(int $iUserId, string $sDriver): void
    {
        /** @var Database $oDb */
        $oDb    = Factory::service('Database');
        $sTable = $this->getTableName();

        $oDb->where('user_id', $iUserId);
        $oDb->update($sTable, ['is_default' => 0]);

        $oDb->where('user_id', $iUserId);
        $oDb->where('driver', $sDriver);
        $oDb->update($sTable, ['is_default' => 1]);
    }
}
