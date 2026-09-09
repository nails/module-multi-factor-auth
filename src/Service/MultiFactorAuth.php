<?php

namespace Nails\MFA\Service;

use DateMalformedIntervalStringException;
use Nails\Auth;
use Nails\Auth\Model\User\Password;
use Nails\Auth\Resource\User;
use Nails\Common\Exception\Encrypt\DecodeException;
use Nails\Common\Exception\EnvironmentException;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Exception\ModelException;
use Nails\Common\Exception\NailsException;
use Nails\Common\Factory\Component;
use Nails\Common\Helper\Strings;
use Nails\Common\Service\Cookie;
use Nails\Common\Service\Database;
use Nails\Common\Service\Encrypt;
use Nails\Common\Service\Input;
use Nails\Config;
use Nails\Factory;
use Nails\MFA;
use Nails\MFA\Constants;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Exception\TokenException;
use Nails\MFA\Exception\TokenMintLimitException;
use Nails\MFA\Resource\Token;
use ReflectionException;
use Throwable;

class MultiFactorAuth
{
    const int    TOKEN_TTL                    = 300;
    const int    MAX_VERIFICATION_ATTEMPTS    = 5;
    const int    MAX_TOKEN_MINTS_PER_HOUR     = 5;
    const string MFA_URL                      = 'mfa';
    const string MFA_COOKIE_TOKEN_KEY         = 'mfa-token';
    const string MFA_COOKIE_IS_PRIVILEGED_KEY = 'mfa-is-privileged';
    const int    MFA_COOKIE_IS_PRIVILEGED_TTL = 1209600; // 14 days
    const string TOKEN_DATA_KEY_RETURN_TO     = 'return_to';
    const string TOKEN_DATA_KEY_IS_REMEMBERED = 'is_remembered';

    // --------------------------------------------------------------------------

    protected Logger $oLogger;

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function __construct()
    {
        /** @var Logger $oLogger */
        $oLogger       = Factory::service('Logger', Constants::MODULE_SLUG);
        $this->oLogger = $oLogger;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws NailsException
     * @throws ReflectionException
     */
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

            $oToken = $this->generateToken(
                $oUser,
                $bIsRemembered,
                $oInput::ipAddress()
            );

            if (!$this->setTokenCookie($oToken)) {
                /** @var MFA\Model\Token $oTokenModel */
                $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
                if ($oToken->id) {
                    $oTokenModel->delete($oToken->id);
                }
                throw new MfaException(
                    'We could not continue your sign-in. Please enable cookies and try again.'
                );
            }

            $this->oLogger->info('Redirecting to: ' . static::MFA_URL);
            redirect(static::MFA_URL);
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

    /**
     * @throws FactoryException
     * @throws ModelException
     * @throws DateMalformedIntervalStringException
     */
    private function generateToken(User $oUser, bool $bIsRemembered, string $sIp): Token
    {
        $this->oLogger->info(sprintf(
            'Generating MFA Token; user: %s; remembered: %s; ip: %s',
            $oUser->id,
            json_encode($bIsRemembered),
            $sIp
        ));

        /** @var Input $oInput */
        $oInput = Factory::service('Input');
        /** @var Database $oDb */
        $oDb = Factory::service('Database');
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Password $oPasswordModel */
        $oPasswordModel = Factory::model('UserPassword', Auth\Constants::MODULE_SLUG);
        /** @var Auth\Model\User $oUserModel */
        $oUserModel = Factory::model('User', Auth\Constants::MODULE_SLUG);

        /** @var \DateTime $oNow */
        $oNow     = Factory::factory('DateTime');
        $oExpires = (clone $oNow)->add(new \DateInterval(sprintf('PT%dS', static::TOKEN_TTL)));

        $oData = (object) [
            //  Mirrors module-auth's own post-login destination; the MFA redirect
            //  happens during the log in event, so that never gets a chance to run
            static::TOKEN_DATA_KEY_RETURN_TO     => $oInput::get('return_to') ?: $oUser->group_homepage,
            static::TOKEN_DATA_KEY_IS_REMEMBERED => $bIsRemembered,
        ];

        $oDb->transaction()->start();

        try {
            //  Serialise token minting for this user so parallel login requests
            //  cannot race past the hourly cap.
            $oDb->query(
                sprintf('SELECT `id` FROM `%s` WHERE `id` = ? FOR UPDATE', $oUserModel->getTableName()),
                [$oUser->id]
            );

            //  Deleted rows remain for the duration of the mint window so
            //  exhausting or completing a token cannot free another slot.
            $oDb->query(
                sprintf(
                    'DELETE FROM `%s` WHERE `user_id` = ? AND `created` < DATE_SUB(NOW(), INTERVAL 1 HOUR)',
                    $oTokenModel->getTableName()
                ),
                [$oUser->id]
            );

            $oDb->where('user_id', $oUser->id);
            $oDb->where('created >=', 'DATE_SUB(NOW(), INTERVAL 1 HOUR)', false);

            if ($oDb->count_all_results($oTokenModel->getTableName()) >= static::MAX_TOKEN_MINTS_PER_HOUR) {
                throw new TokenMintLimitException(
                    'We could not complete your sign-in. Please wait and try again later.'
                );
            }

            //  @todo (Pablo 2023-02-22) - tolerate save failure (duplicate?) perhaps do {} while() and an incrementing counter

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

            $this->oLogger->info(sprintf(
                'Setting token data; %s',
                json_encode($oData)
            ));

            $oToken->setData($oData);
            $oDb->transaction()->commit();

            return $oToken;

        } catch (Throwable $e) {
            $oDb->transaction()->rollback();
            throw $e;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * @throws DecodeException
     * @throws EnvironmentException
     * @throws FactoryException
     * @throws ModelException
     * @throws TokenException
     * @throws TokenException\DoesNotExistException
     * @throws TokenException\InvalidSaltException
     * @throws TokenException\IsExpiredException
     */
    public function getToken(string $sEncryptedToken): Token
    {
        if (empty($sEncryptedToken)) {
            throw new TokenException('Token cannot be empty');
        }

        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $sDecryptedToken = $oEncrypt::decode($sEncryptedToken);
        [$sSalt, $sToken] = array_pad(explode(Token::DELIMITER, $sDecryptedToken), 2, null);

        if (empty($sSalt) || empty($sToken)) {
            throw new TokenException('Token is malformed');
        }

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
        }

        return $oToken;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws DecodeException
     * @throws EnvironmentException
     * @throws FactoryException
     * @throws ModelException
     * @throws TokenException
     */
    public function getTokenFromCookie(): Token
    {
        /** @var Cookie $oCookie */
        $oCookie      = Factory::service('Cookie');
        $oStoredToken = $oCookie->read(static::MFA_COOKIE_TOKEN_KEY);

        if (empty($oStoredToken) || empty($oStoredToken->value)) {
            throw new TokenException\MissingCookieException(
                'We could not continue your sign-in. Please enable cookies and try again.'
            );
        }

        return $this->getToken($oStoredToken->value);
    }

    // --------------------------------------------------------------------------

    /**
     * Atomically claims a verification attempt and invalidates exhausted tokens.
     * This must be called before the driver compares the code. Recording only
     * after a mismatch allows parallel requests to perform unlimited comparisons
     * before any of them increment the counter.
     *
     * @throws FactoryException
     * @throws ModelException
     * @throws TokenException\TooManyAttemptsException
     */
    public function registerFailedAttempt(Token $oToken): void
    {
        /** @var Database $oDb */
        $oDb = Factory::service('Database');
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        $sTable      = $oTokenModel->getTableName();

        if (empty($oToken->id)) {
            throw (new TokenException\TooManyAttemptsException(
                'Too many incorrect codes. Please sign in again.'
            ))->setToken($oToken);
        }

        $oDb->set('attempts', 'attempts + 1', false);
        $oDb->where('id', $oToken->id);
        $oDb->where('attempts <', static::MAX_VERIFICATION_ATTEMPTS);
        $oDb->update($sTable);

        $bAttemptClaimed = $oDb->affected_rows() === 1;
        $oDb->select('attempts');
        $oDb->where('id', $oToken->id);
        /** @var mixed $oResult */
        $oResult   = $oDb->get($sTable);
        $oAttempts = $oResult->row();

        if (!$bAttemptClaimed || empty($oAttempts)) {
            if (!empty($oAttempts)) {
                $oTokenModel->delete($oToken->id);
            }

            throw (new TokenException\TooManyAttemptsException(
                'Too many incorrect codes. Please sign in again.'
            ))->setToken($oToken);
        }

        $oToken->attempts = (int) $oAttempts->attempts;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function setTokenCookie(Token $oToken): bool
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');

        return $oCookie->write(
            static::MFA_COOKIE_TOKEN_KEY,
            (string) $oToken,
            static::TOKEN_TTL,
            '/',
            '',
            true,
            true,
            'Lax'
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function clearTokenCookie(): void
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');
        $oCookie->delete(static::MFA_COOKIE_TOKEN_KEY, '/');
    }

    // --------------------------------------------------------------------------

    /**
     * @return MFA\Interfaces\Authentication\Driver[]
     * @throws NailsException
     * @throws MFA\Exception\MfaException
     */
    public function getAuthenticationMethods(User $oUser): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);

        $aDrivers = [];
        /** @var Component[] $aEnabled */
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

    /**
     * @throws DecodeException
     * @throws EnvironmentException
     * @throws FactoryException
     */
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

        $sActiveUserHash      = $this->getIsPrivilegedHash(activeUser());
        $oStoredHashEncrypted = $oCookie->read(static::MFA_COOKIE_IS_PRIVILEGED_KEY);

        if (empty($oStoredHashEncrypted)) {
            return false;
        }

        $sStoredHash = $oEncrypt::decode($oStoredHashEncrypted->value);

        $bResult = isLoggedIn() && $sActiveUserHash === $sStoredHash;

        $this->oLogger->info('User is privileged: ' . json_encode($bResult));

        return $bResult;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws EnvironmentException
     * @throws FactoryException
     */
    public function setIsPrivileged(User $oUser, bool $bRemember = true): self
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $sKey   = static::MFA_COOKIE_IS_PRIVILEGED_KEY;
        $sValue = $this->getIsPrivilegedHash($oUser);

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
                    ? static::MFA_COOKIE_IS_PRIVILEGED_TTL
                    : null,
                '/'
            );

        return $this;
    }

    // --------------------------------------------------------------------------

    protected function getIsPrivilegedHash(User $oUser): string
    {
        return sha1(Config::get('PRIVATE_KEY') . $oUser->id . $oUser->salt);
    }
}
