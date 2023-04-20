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
use Nails\Common\Service\Cookie;
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
    const MFA_COOKIE_IS_PRIVILGED_KEY  = 'mfa-is-priviliged';
    const MFA_COOKIE_IS_PRIVILGED_TTL  = 2592000; // 30 days
    const TOKEN_DATA_KEY_RETURN_TO     = 'return_to';
    const TOKEN_DATA_KEY_IS_REMEMBERED = 'is_remembered';

    // --------------------------------------------------------------------------

    protected Logger $oLogger;

    // --------------------------------------------------------------------------

    public function __construct()
    {
        $this->oLogger = Factory::service('Logger', Constants::MODULE_SLUG);
    }

    // --------------------------------------------------------------------------

    public function authenticate(User $oUser, bool $bIsRemembered, bool $bForce = false): self
    {
        $this->oLogger->info(sprintf(
            'Authenticating user %s; remembered: %s; forced: %s',
            $oUser->id,
            json_encode($bIsRemembered),
            json_encode($bForce),
        ));

        if ($bForce || $this->requiresAuthentication()) {

            $this->oLogger->info('Authentication required, continuing');

            /** @var Input $oInput */
            $oInput = Factory::service('Input');
            /** @var Auth\Service\Authentication $oAuth */
            $oAuth = Factory::service('Authentication', Auth\Constants::MODULE_SLUG);

            if (isLoggedIn()) {
                $this->oLogger->info('User is currently logged in, logging out');
                $oAuth->logout();
            }

            $sUrl = sprintf(
                static::MFA_URL,
                urlencode(
                    $this->generateToken(
                        $oUser,
                        $bIsRemembered,
                        $oInput::ipAddress()
                    )
                )
            );

            $this->oLogger->info('Redirecting to: ' . $sUrl);
            redirect($sUrl);
        }

        return $this;
    }

    // --------------------------------------------------------------------------

    public function isAuthenticated(): bool
    {
        $bResult = isLoggedIn() && $this->isPrivileged();

        $this->oLogger->info('Is Authenticated: ' . json_encode($bResult));

        return $bResult;
    }

    // --------------------------------------------------------------------------

    public function requiresAuthentication(): bool
    {
        $bResult = !$this->isAuthenticated() && !wasAdmin();
        $this->oLogger->info('Requires Authentication: ' . json_encode($bResult));
        return $bResult;
    }

    // --------------------------------------------------------------------------

    private function generateToken(User $oUser, bool $bIsRememebred, string $sIp): Token
    {
        $this->oLogger->info(sprintf(
            'Generating MFA Token; user: %s; remembered: %s; ip: %s',
            $oUser->id,
            json_encode($bIsRememebred),
            $sIp
        ));

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

        $this->oLogger->info(sprintf(
            'Token generated with ID %s',
            $oToken->id,
        ));

        //  @todo (Pablo 2023-02-23) - persist session data?

        $oData = (object) [
            static::TOKEN_DATA_KEY_RETURN_TO     => $oInput::get('return_to') ?: $oInput::server('URI_STRING'),
            static::TOKEN_DATA_KEY_IS_REMEMBERED => $bIsRememebred,
        ];

        $this->oLogger->info(sprintf(
            'Setting token data; %s',
            json_encode($oData)
        ));

        $oToken->setData($oData);

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
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $this->oLogger->info(sprintf(
            'Checking if active user is privileged; active user %s',
            activeUser()->id,
        ));

        $sActiveUserHash      = $this->getIsPriviligedHash(activeUser());
        $oStoredHashEncrypted = $oCookie->read(static::MFA_COOKIE_IS_PRIVILGED_KEY);

        if (empty($oStoredHashEncrypted)) {
            return false;
        }

        $sStoredHash = $oEncrypt::decode($oStoredHashEncrypted->value);

        $bResult = isLoggedIn() && $sActiveUserHash === $sStoredHash;

        $this->oLogger->info('User is priviliged: ' . json_encode($bResult));

        return $bResult;
    }

    // --------------------------------------------------------------------------

    public function setIsPriviliged(User $oUser, bool $bRemember = true): self
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $sKey   = static::MFA_COOKIE_IS_PRIVILGED_KEY;
        $sValue = $this->getIsPriviligedHash($oUser);

        $this->oLogger->info(sprintf(
            'Setting user as privileged; user %s; key: %s; value: %s',
            $oUser->id,
            $sKey,
            md5($sValue)
        ));

        $oCookie
            ->write(
                $sKey,
                $oEncrypt::encode($sValue),
                $bRemember
                    ? static::MFA_COOKIE_IS_PRIVILGED_TTL
                    : null,
                '/'
            );

        return $this;
    }

    // --------------------------------------------------------------------------

    protected function getIsPriviligedHash(User $oUser): string
    {
        return sha1(Config::get('PRIVATE_KEY') . $oUser->id . $oUser->salt);
    }
}
