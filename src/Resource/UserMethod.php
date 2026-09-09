<?php

namespace Nails\MFA\Resource;

use Nails\Auth\Resource\User;
use Nails\Common\Exception\Encrypt\DecodeException;
use Nails\Common\Exception\EnvironmentException;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Resource;
use Nails\Common\Service\Encrypt;
use Nails\Factory;
use Nails\MFA\Constants;
use stdClass;

class UserMethod extends Resource\Entity
{
    public ?int    $user_id    = null;
    public ?User   $user       = null;
    public ?string $driver     = null;
    public bool    $is_default = false;
    public ?string $data       = null;

    // --------------------------------------------------------------------------

    /**
     * @throws DecodeException
     * @throws EnvironmentException
     * @throws FactoryException
     */
    public function getDecodedData(): stdClass
    {
        if ($this->data === null || $this->data === '') {
            return (object) [];
        }

        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        return (object) json_decode($oEncrypt::decode($this->data), false);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws EnvironmentException
     * @throws FactoryException
     */
    public function setDecodedData(stdClass $oData): self
    {
        /** @var Encrypt $oEncrypt */
        $oEncrypt   = Factory::service('Encrypt');
        $this->data = $oEncrypt::encode(json_encode($oData) ?: '{}');

        if ($this->id) {
            $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);
            $oModel->update($this->id, ['data' => $this->data]);
        }

        return $this;
    }
}
