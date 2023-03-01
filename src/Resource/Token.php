<?php

namespace Nails\MFA\Resource;

use Nails\Auth\Resource\User;
use Nails\Common\Model\Base;
use Nails\Common\Resource;
use Nails\Common\Service\Encrypt;
use Nails\Factory;
use Nails\MFA\Constants;

class Token extends Resource\Entity
{
    const DELIMITER = '.';

    // --------------------------------------------------------------------------

    public ?int               $user_id = null;
    public ?User              $user    = null;
    public ?string            $token   = null;
    public ?string            $salt    = null;
    public ?string            $ip      = null;
    public ?Resource\DateTime $expires = null;
    public ?string            $data    = null;

    // --------------------------------------------------------------------------

    /**
     * @param array<mixed>|\Nails\Common\Resource|\stdClass $mObj
     */
    public function __construct($mObj = [])
    {
        parent::__construct($mObj);
    }

    // --------------------------------------------------------------------------

    public function user(): ?User
    {
        if (empty($this->user) && !empty($this->user_id)) {

            /** @var \Nails\Auth\Model\User $oModel */
            $oModel = Factory::model('User', \Nails\Auth\Constants::MODULE_SLUG);
            /** @var User $oUser */
            $oUser = $oModel->getById($this->user_id);

            $this->user = $oUser;
        }

        return $this->user;
    }

    // --------------------------------------------------------------------------

    public function setData(\stdClass $oData): self
    {
        $aData = (array) json_decode($this->data ?? '');
        $aData = array_merge($aData, (array) $oData);

        $this->data = json_encode((object) $aData) ?: null;

        if ($this->id) {
            $oModel = Factory::model('Token', Constants::MODULE_SLUG);
            $oModel->update($this->id, ['data' => $this->data]);
        }

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * @return mixed
     */
    public function getData(string $sKey = null)
    {
        $oData = (object) json_decode($this->data ?? '');
        return $sKey ? ($oData->{$sKey} ?? null) : $oData;
    }

    // --------------------------------------------------------------------------

    public function __toString()
    {
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');
        return $oEncrypt::encode($this->salt . static::DELIMITER . $this->token);
    }
}
