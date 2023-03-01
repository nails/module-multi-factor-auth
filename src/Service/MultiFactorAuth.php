<?php

namespace Nails\MFA\Service;

use Nails\Auth;
use Nails\Config;
use Nails\MFA;
use Nails\MFA\Exception\TokenException;
use Nails\Auth\Model\User\Password;
use Nails\MFA\Constants;
use Nails\MFA\Resource\Token;
use Nails\Auth\Resource\User;
use Nails\Common\Helper\Strings;
use Nails\Common\Service\Database;
use Nails\Common\Service\Encrypt;
use Nails\Common\Service\Input;
use Nails\Components;
use Nails\Factory;

class MultiFactorAuth
{
    const TOKEN_TTL                    = 300;
    const MFA_URL                      = 'mfa/%s';
    const MFA_URL_TOKEN_SEGMENT        = 2;
    const MFA_SESSION_IS_PRIVILGED_KEY = 'mfa-is-priviliged';

    // --------------------------------------------------------------------------

    public function authenticate(bool $bForce = false, User $oUser = null): self
    {
        if ($bForce || $this->requiresAuthentication()) {

            $oUser = $oUser ?? activeUser();
            /** @var Input $oInput */
            $oInput = Factory::service('Input');
            /** @var Auth\Service\Authentication $oAuth */
            $oAuth = Factory::service('Authentication', Auth\Constants::MODULE_SLUG);

            if (isLoggedIn()) {
                $oAuth->logout();
            }

            redirect(
                sprintf(
                    static::MFA_URL,
                    urlencode(
                        $this->generateToken(
                            $oUser,
                            $oInput::ipAddress()
                        )
                    )
                )
            );
        }

        return $this;
    }

    // --------------------------------------------------------------------------

    public function isAuthenticated(): bool
    {
        /** @var \Nails\Auth\Service\Session $oSession */
        $oSession = Factory::service('Session');
        return isLoggedIn() && $this->isPrivileged();
    }

    // --------------------------------------------------------------------------

    public function requiresAuthentication(): bool
    {
        return !$this->isAuthenticated() && !wasAdmin();
    }

    // --------------------------------------------------------------------------

    private function generateToken(User $oUser, string $sIp): Token
    {
        /** @var Input $oInput */
        $oInput = Factory::service('Input');
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Password $oPasswordModel */
        $oPasswordModel = Factory::model('UserPassword', \Nails\Auth\Constants::MODULE_SLUG);

        /** @var \DateTime $oNow */
        $oNow     = Factory::factory('DateTime');
        $oExpires = (clone $oNow)->add(new \DateInterval(sprintf('PT%dS', static::TOKEN_TTL)));

        //  @todo (Pablo 2023-02-22) - tolerate save failure (duplicate?) perhaps do {} while() and an incementing counter

        /** @var Token $oToken */
        $oToken = $oTokenModel
            ->create([
                'user_id' => $oUser->id,
                'token'   => Strings::generateToken(),
                'salt'    => $oPasswordModel->salt(),
                'created' => $oNow->format('Y-m-d H:i:s'),
                'expires' => $oExpires->format('Y-m-d H:i:s'),
                'ip'      => $sIp,
            ], true);

        //  @todo (Pablo 2023-02-23) - persist session data?

        $oToken->setData((object) [
            'return_to' => $oInput::get('return_to') ?: $oInput::server('URI_STRING'),
        ]);

        return $oToken;
    }

    // --------------------------------------------------------------------------

    public function getToken(string $sEncryptedToken, string $sIp): Token
    {
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $sDecryptedToken = $oEncrypt::decode($sEncryptedToken);
        [$sSalt, $sToken] = array_pad(explode(Token::DELIMITER, $sDecryptedToken), 2, null);

        /** @var Token|null $oToken */
        $oToken = $oTokenModel->getByToken($sToken);

        if (empty($oToken)) {
            throw new TokenException\DoesNotExistException('Token does not exist');

        } elseif ($oToken->expires && $oToken->expires->isPast()) {
            throw (new TokenException\IsExpiredException('Token has expired'))
                ->setToken($oToken);

        } elseif ($oToken->salt !== $sSalt) {
            throw (new TokenException\InvalidSaltException('Token salt does not match supplied salt'))
                ->setToken($oToken);

        } elseif ($oToken->ip !== $sIp) {
            throw (new TokenException\InvalidIpException('Token IP does not match supplied IP'))
                ->setToken($oToken);
        }

        return $oToken;
    }

    // --------------------------------------------------------------------------

    /**
     * @return MFA\Interfaces\Authentication\Driver[]
     * @throws \Nails\Common\Exception\NailsException
     * @throws MFA\Exception\MfaException
     */
    public function getAuthenticationMethods(User $oUser): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);

        $aDrivers = [];
        /** @var \Nails\Common\Factory\Component[] $aEnabled */
        $aEnabled = $oService->getEnabled();
        foreach ($aEnabled as $oComponent) {
            $aDrivers[] = $oService->getInstance($oComponent);
        }

        //  @todo (Pablo 2023-02-22) - filter out drivers which are not configured for this user

        if (empty($aDrivers)) {
            throw new MFA\Exception\MfaException('No MFA drivers are available');
        }

        return $aDrivers;
    }

    // --------------------------------------------------------------------------

    public function isPrivileged(): bool
    {
        /** @var \Nails\Auth\Service\Session $oSession */
        $oSession = Factory::service('Session');

        return isLoggedIn() && $this->getIsPriviligedHash(activeUser()) === $oSession->getUserData(static::MFA_SESSION_IS_PRIVILGED_KEY);
    }

    // --------------------------------------------------------------------------

    public function setIsPriviliged(User $oUser): self
    {
        /** @var \Nails\Auth\Service\Session $oSession */
        $oSession = Factory::service('Session');
        $oSession->setUserData(static::MFA_SESSION_IS_PRIVILGED_KEY, $this->getIsPriviligedHash($oUser));
        return $this;
    }

    // --------------------------------------------------------------------------

    protected function getIsPriviligedHash(User $oUser): string
    {
        return sha1(Config::get('PRIVATE_KEY') . $oUser->id . $oUser->salt);
    }
}
