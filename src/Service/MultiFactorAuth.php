<?php

namespace Nails\MFA\Service;

use DateMalformedIntervalStringException;
use Nails\Auth;
use Nails\Auth\Model\User\Password;
use Nails\Auth\Resource\User;
use Nails\Common\Exception\EnvironmentException;
use Nails\Common\Exception\FactoryException;
use Nails\Common\Exception\ModelException;
use Nails\Common\Exception\NailsException;
use Nails\Common\Factory\Component;
use Nails\Common\Helper\Model\Limit;
use Nails\Common\Helper\Model\Sort;
use Nails\Common\Helper\Model\Where;
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
use stdClass;
use Throwable;

class MultiFactorAuth
{
    const int    TOKEN_TTL                    = 300;
    const int    TOKEN_REUSE_MIN_TTL          = 30;
    const int    MAX_VERIFICATION_ATTEMPTS    = 5;
    const int    MAX_RESENDS_PER_TOKEN        = 3;
    const int    MAX_TOKEN_MINTS_PER_HOUR     = 10;
    const int    LOGIN_SIGNAL_MAX_AGE         = 120;
    const string MFA_URL                      = 'mfa';
    const string MFA_COOKIE_TOKEN_KEY         = 'mfa-token';
    const string MFA_COOKIE_IS_PRIVILEGED_KEY = 'mfa-is-privileged';
    const int    MFA_COOKIE_IS_PRIVILEGED_TTL = 1209600; // 14 days
    const string TOKEN_DATA_KEY_RETURN_TO      = 'return_to';
    const string TOKEN_DATA_KEY_IS_REMEMBERED  = 'is_remembered';
    const string TOKEN_DATA_KEY_DRIVER         = 'driver';
    const string TOKEN_DATA_KEY_PENDING_SETUP  = 'pending_setup';
    const string TOKEN_DATA_KEY_IS_SETUP        = 'is_setup';
    const string TOKEN_DATA_KEY_RESENDS         = 'resends';

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

            /**
             * Minted before logout(), deliberately: generateToken() can throw (e.g.
             * TokenMintLimitException), and logout() destroys the session. Doing it
             * the other way round meant a failure here left nothing for the caller's
             * catch block to show the user — the flash message it sets afterwards
             * was written into a session that had already been torn down.
             */
            $oToken = $this->generateToken(
                $oUser,
                $bIsRemembered,
                $oInput::ipAddress()
            );

            if (isLoggedIn()) {
                $this->oLogger->info('User is currently logged in, logging out');
                $oAuth->logout();
            }

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
        $bResult = !$this->isAuthenticated()
            && !wasAdmin()
            && isLoggedIn()
            && $this->userRequiresChallenge(activeUser())
            && !$this->loginSatisfiesChallenge();

        $this->oLogger->info('Requires Authentication: ' . json_encode($bResult));
        return $bResult;
    }

    // --------------------------------------------------------------------------

    /**
     * Whether the way the current session signed in already stands in for the
     * MFA challenge, so the user should not be challenged again.
     *
     * A user-verified passkey login is phishing-resistant and proves possession
     * of a second factor, so it satisfies the challenge on its own. The skip is
     * per-login only: setIsPrivileged() is deliberately not called, so a later
     * password login on the same browser is still challenged.
     *
     * @throws FactoryException
     */
    public function loginSatisfiesChallenge(): bool
    {
        /** @var Auth\Service\Authentication $oAuth */
        $oAuth = Factory::service('Authentication', Auth\Constants::MODULE_SLUG);

        $bResult = static::loginSignalSatisfies(
            $oAuth->getLoginMethod(),
            (int) activeUser()->id,
            time()
        );

        $this->oLogger->info('Login satisfies MFA challenge: ' . json_encode($bResult));

        return $bResult;
    }

    // --------------------------------------------------------------------------

    /**
     * The pure predicate behind loginSatisfiesChallenge(): true only for a
     * fresh, user-verified passkey login belonging to this same user.
     *
     * Kept static and free of DB/session/Factory access so it can be unit
     * tested directly.
     *
     * @param stdClass|null $oSignal The login-method signal from Authentication::getLoginMethod()
     * @param int           $iUserId The id of the user about to be challenged
     * @param int           $iNow    The current unix timestamp
     */
    public static function loginSignalSatisfies(?stdClass $oSignal, int $iUserId, int $iNow): bool
    {
        if ($oSignal === null || $iUserId <= 0) {
            return false;
        }

        $sMethod       = is_string($oSignal->method ?? null) ? $oSignal->method : null;
        $iSignalUserId = (int) ($oSignal->user_id ?? 0);
        $iAt           = (int) ($oSignal->at ?? 0);

        if ($sMethod !== Auth\Service\Authentication::LOGIN_METHOD_PASSKEY) {
            return false;
        }

        if (empty($oSignal->user_verified)) {
            return false;
        }

        if ($iSignalUserId !== $iUserId) {
            return false;
        }

        //  Reject a signal with no timestamp, one from the future (clock skew or
        //  tampering), or one older than the freshness window.
        return $iAt > 0
            && $iNow >= $iAt
            && ($iNow - $iAt) <= static::LOGIN_SIGNAL_MAX_AGE;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function userRequiresChallenge(User $oUser): bool
    {
        $sMode = $this->getGroupMode($oUser);

        if ($sMode === MFA\Model\GroupPolicy::MODE_DISABLED) {
            return false;
        }

        if ($sMode === MFA\Model\GroupPolicy::MODE_OPTIONAL && empty($this->getUserMethods($oUser))) {
            return false;
        }

        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getGroupMode(User $oUser): string
    {
        /** @var MFA\Model\GroupPolicy $oPolicyModel */
        $oPolicyModel = Factory::model('GroupPolicy', Constants::MODULE_SLUG);

        return $oPolicyModel->getModeForGroup((int) $oUser->group_id);
    }

    // --------------------------------------------------------------------------

    /**
     * Whether the user's group allows them to manage MFA methods.
     *
     * @throws FactoryException
     * @throws ModelException
     */
    public function userCanManageMethods(User $oUser): bool
    {
        $sMode = $this->getGroupMode($oUser);

        return $sMode === MFA\Model\GroupPolicy::MODE_OPTIONAL
            || $sMode === MFA\Model\GroupPolicy::MODE_REQUIRED;
    }

    // --------------------------------------------------------------------------

    /**
     * Whether the user has anything they can change on the management screen:
     * adding a method, removing one, or choosing a different default.
     *
     * @throws FactoryException
     * @throws ModelException
     */
    public function userCanConfigureMethods(User $oUser): bool
    {
        if (!$this->userCanManageMethods($oUser)) {
            return false;
        }

        $aMethods = $this->getUserMethods($oUser);

        //  Several methods can be removed, or have the default moved between them
        if (count($aMethods) > 1) {
            return true;
        }

        foreach ($aMethods as $oMethod) {
            if ($this->userCanRemoveMethod($oUser, (string) $oMethod->driver)) {
                return true;
            }
        }

        try {
            return !empty($this->getSetupDrivers($oUser));
        } catch (MFA\Exception\MfaException $e) {
            //  With no enabled drivers there is nothing new to set up
            return false;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * Whether a method can be given up: a user cannot be left with none while
     * their group requires MFA.
     *
     * @throws FactoryException
     * @throws ModelException
     */
    public function userCanRemoveMethod(User $oUser, string $sDriver): bool
    {
        if (!$this->getUserMethod($oUser, $sDriver)) {
            return false;
        }

        return count($this->getUserMethods($oUser)) > 1
            || $this->getGroupMode($oUser) !== MFA\Model\GroupPolicy::MODE_REQUIRED;
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

        $sReturnTo = trim((string) $oInput::get('return_to'));
        /** @var \DateTime $oNow */
        $oNow     = Factory::factory('DateTime');
        $oExpires = (clone $oNow)->add(new \DateInterval(sprintf('PT%dS', static::TOKEN_TTL)));

        $oData = (object) [
            static::TOKEN_DATA_KEY_IS_REMEMBERED => $bIsRemembered,
        ];

        /**
         * A reused challenge may be reached after the user cancelled, went back,
         * or opened the login page directly. In those cases there is no return_to
         * on the new request, but the token still knows where the original login
         * was going. Only replace it when a new destination was explicitly given.
         */
        if ($sReturnTo !== '') {
            $oData->{static::TOKEN_DATA_KEY_RETURN_TO} = $sReturnTo;
        }

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

            /**
             * A user only ever needs one outstanding challenge, so an abandoned
             * one is handed back rather than minting another. Without this, simply
             * signing in again consumes the hourly allowance and locks the user
             * out of their own account. The expiry is deliberately not extended.
             */
            $oExisting = $this->getLiveToken($oUser);

            if ($oExisting) {

                $this->oLogger->info(sprintf(
                    'Reusing live token with ID %s',
                    $oExisting->id,
                ));

                $this->oLogger->info(sprintf(
                    'Setting token data; %s',
                    json_encode($oData)
                ));

                $oExisting->setData($oData);
                $oDb->transaction()->commit();

                return $oExisting;
            }

            $oDb->where('user_id', $oUser->id);
            $oDb->where('created >=', 'DATE_SUB(NOW(), INTERVAL 1 HOUR)', false);

            if ($oDb->count_all_results($oTokenModel->getTableName()) >= $this->getMaxTokenMintsPerHour()) {
                throw new TokenMintLimitException(
                    'We could not complete your sign-in. Please wait and try again later.'
                );
            }

            //  A new token has no earlier destination to preserve.
            if ($sReturnTo === '') {
                $oData->{static::TOKEN_DATA_KEY_RETURN_TO} = $oUser->group_homepage;
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
     * The user's outstanding challenge, if they have one which is still worth
     * completing, i.e. it has enough life left in it and has not had its
     * verification attempts exhausted.
     *
     * @throws FactoryException
     * @throws ModelException
     */
    protected function getLiveToken(User $oUser): ?Token
    {
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);

        /** @var \DateTime $oThreshold */
        $oThreshold = Factory::factory('DateTime');
        $oThreshold->add(new \DateInterval(sprintf('PT%dS', static::TOKEN_REUSE_MIN_TTL)));

        /** @var Token|null $oToken */
        $oToken = $oTokenModel->getAll([
            new Where('user_id', $oUser->id),
            new Where('expires >', $oThreshold->format('Y-m-d H:i:s')),
            new Where('attempts <', static::MAX_VERIFICATION_ATTEMPTS),
            new Sort('id', Sort::DESC),
            new Limit(1),
        ])[0] ?? null;

        return $oToken;
    }

    // --------------------------------------------------------------------------

    /**
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

        $sDecryptedToken = $this->decryptUntrustedValue(
            $sEncryptedToken,
            sprintf('the "%s" cookie', static::MFA_COOKIE_TOKEN_KEY)
        );

        if ($sDecryptedToken === null) {
            throw new TokenException('Token could not be decrypted');
        }

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
     * Claims one of the challenge's replacement codes, if any are left. The
     * allowance exists because each one sends the user a message they did not
     * necessarily ask for.
     */
    public function claimResend(Token $oToken): bool
    {
        $iResends = (int) $oToken->getData(static::TOKEN_DATA_KEY_RESENDS);

        if ($iResends >= static::MAX_RESENDS_PER_TOKEN) {
            return false;
        }

        $oToken->setData((object) [
            static::TOKEN_DATA_KEY_RESENDS => $iResends + 1,
        ]);

        return true;
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
     * @throws FactoryException
     */
    public function clearIsPrivilegedCookie(): void
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');
        $oCookie->delete(static::MFA_COOKIE_IS_PRIVILEGED_KEY, '/');
    }

    // --------------------------------------------------------------------------

    /**
     * Decrypts a value which originated from user input, e.g. a cookie.
     *
     * Such values are routinely truncated, tampered with, or encrypted using a
     * since-rotated key; the crypto library treats all of those as exceptions.
     * They are not exceptional here, so return null and let the caller decide
     * how to recover. Callers must treat null as "no valid value".
     */
    protected function decryptUntrustedValue(string $sCipher, string $sDescription): ?string
    {
        if ($sCipher === '') {
            return null;
        }

        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        try {
            return $oEncrypt::decode($sCipher);

        } catch (Throwable $e) {
            $this->oLogger->warning(sprintf(
                'Could not decrypt %s; treating it as absent: [%s] %s',
                $sDescription,
                $e::class,
                $e->getMessage()
            ));

            return null;
        }
    }

    // --------------------------------------------------------------------------

    /**
     * @return MFA\Interfaces\Authentication\Driver[]
     * @throws NailsException
     * @throws MFA\Exception\MfaException
     */
    public function getEnabledDrivers(): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);

        $aDrivers = [];
        /** @var Component[] $aEnabled */
        $aEnabled = $oService->getEnabled();
        foreach ($aEnabled as $oComponent) {
            $aDrivers[] = $oService->getInstance($oComponent);
        }

        if (empty($aDrivers)) {
            throw new MFA\Exception\MfaException('No MFA drivers are available');
        }

        return $aDrivers;
    }

    // --------------------------------------------------------------------------

    /**
     * Enabled drivers the user has enrolled in.
     *
     * @return MFA\Interfaces\Authentication\Driver[]
     * @throws NailsException
     * @throws MFA\Exception\MfaException
     */
    public function getAuthenticationMethods(User $oUser): array
    {
        $aEnrolledSlugs = array_map(
            fn(MFA\Resource\UserMethod $oMethod) => $oMethod->driver,
            $this->getUserMethods($oUser)
        );

        $aDrivers = [];
        foreach ($this->getEnabledDrivers() as $oDriver) {
            $sSlug = $oDriver->getSlug();
            if (in_array($sSlug, $aEnrolledSlugs, true)) {
                $aDrivers[] = $oDriver;
            }
        }

        return $aDrivers;
    }

    // --------------------------------------------------------------------------

    /**
     * Enabled drivers the user can still enroll in.
     *
     * @return MFA\Interfaces\Authentication\Driver[]
     * @throws NailsException
     */
    public function getSetupDrivers(User $oUser): array
    {
        $aEnrolledSlugs = array_map(
            fn(MFA\Resource\UserMethod $oMethod) => $oMethod->driver,
            $this->getUserMethods($oUser)
        );

        $aDrivers = [];
        foreach ($this->getEnabledDrivers() as $oDriver) {
            if (!in_array($oDriver->getSlug(), $aEnrolledSlugs, true)) {
                $aDrivers[] = $oDriver;
            }
        }

        return $aDrivers;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     * @throws MFA\Exception\MfaException
     */
    public function getDriverBySlug(string $sSlug): MFA\Interfaces\Authentication\Driver
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $oDriver  = $oService->getInstance($sSlug);

        if (empty($oDriver)) {
            throw new MFA\Exception\MfaException('Unknown MFA driver: ' . $sSlug);
        }

        return $oDriver;
    }

    // --------------------------------------------------------------------------

    /**
     * @return MFA\Resource\UserMethod[]
     * @throws FactoryException
     * @throws ModelException
     */
    public function getUserMethods(User $oUser): array
    {
        /** @var MFA\Model\UserMethod $oModel */
        $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);

        return $oModel->getByUserId((int) $oUser->id);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getUserMethod(User $oUser, string $sDriver): ?MFA\Resource\UserMethod
    {
        /** @var MFA\Model\UserMethod $oModel */
        $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);

        return $oModel->getByUserAndDriver((int) $oUser->id, $sDriver);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function getDefaultUserMethod(User $oUser): ?MFA\Resource\UserMethod
    {
        /** @var MFA\Model\UserMethod $oModel */
        $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);

        return $oModel->getDefaultForUser((int) $oUser->id);
    }

    // --------------------------------------------------------------------------

    public function userNeedsSetup(User $oUser): bool
    {
        return $this->getGroupMode($oUser) === MFA\Model\GroupPolicy::MODE_REQUIRED
            && empty($this->getUserMethods($oUser));
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    public function selectDriver(User $oUser, Token $oToken): ?MFA\Interfaces\Authentication\Driver
    {
        $sSelected = $oToken->getData(static::TOKEN_DATA_KEY_DRIVER);
        if (is_string($sSelected) && $sSelected !== '') {
            if ($oToken->getData(static::TOKEN_DATA_KEY_IS_SETUP)) {
                foreach ($this->getSetupDrivers($oUser) as $oDriver) {
                    if ($oDriver->getSlug() === $sSelected) {
                        return $oDriver;
                    }
                }
            }

            foreach ($this->getAuthenticationMethods($oUser) as $oDriver) {
                if ($oDriver->getSlug() === $sSelected) {
                    return $oDriver;
                }
            }
        }

        $oDefault = $this->getDefaultUserMethod($oUser);
        if ($oDefault) {
            try {
                $oDriver = $this->getDriverBySlug((string) $oDefault->driver);
                foreach ($this->getAuthenticationMethods($oUser) as $oEnabled) {
                    if ($oEnabled->getSlug() === $oDriver->getSlug()) {
                        $oToken->setData((object) [
                            static::TOKEN_DATA_KEY_DRIVER => $oDriver->getSlug(),
                        ]);
                        return $oDriver;
                    }
                }
            } catch (MFA\Exception\MfaException $e) {
                $this->oLogger->info('Default MFA driver is not enabled: ' . $e->getMessage());
            }
        }

        $aMethods = $this->getAuthenticationMethods($oUser);
        if (empty($aMethods)) {
            return null;
        }

        $oDriver = reset($aMethods);
        $oToken->setData((object) [
            static::TOKEN_DATA_KEY_DRIVER => $oDriver->getSlug(),
        ]);

        return $oDriver;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function enrollMethod(User $oUser, string $sDriver, stdClass $oData, bool $bMakeDefault = false): MFA\Resource\UserMethod
    {
        /** @var MFA\Model\UserMethod $oModel */
        $oModel     = Factory::model('UserMethod', Constants::MODULE_SLUG);
        $aExisting  = $this->getUserMethods($oUser);
        $bIsDefault = $bMakeDefault || empty($aExisting);

        $oExisting = $this->getUserMethod($oUser, $sDriver);
        if ($oExisting) {
            $oExisting->setDecodedData($oData);
            if ($bIsDefault) {
                $oModel->setDefault((int) $oUser->id, $sDriver);
            }
            /** @var MFA\Resource\UserMethod $oUpdated */
            $oUpdated = $oModel->getById($oExisting->id);
            return $oUpdated;
        }

        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        /** @var MFA\Resource\UserMethod $oMethod */
        $oMethod = $oModel->create([
            'user_id'    => $oUser->id,
            'driver'     => $sDriver,
            'is_default' => $bIsDefault ? 1 : 0,
            'data'       => $oEncrypt::encode(json_encode($oData) ?: '{}'),
        ], true);

        if ($bIsDefault) {
            $oModel->setDefault((int) $oUser->id, $sDriver);
        }

        $this->oLogger->info(sprintf(
            'Enrolled MFA method %s for user %s',
            $sDriver,
            $oUser->id
        ));

        return $oMethod;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     */
    public function setDefaultMethod(User $oUser, string $sDriver): void
    {
        if (!$this->getUserMethod($oUser, $sDriver)) {
            throw new MFA\Exception\MfaException('That method is not enrolled.');
        }

        /** @var MFA\Model\UserMethod $oModel */
        $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);
        $oModel->setDefault((int) $oUser->id, $sDriver);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws ModelException
     * @throws NailsException
     */
    public function removeMethod(User $oUser, string $sDriver, bool $bAllowLastRequired = false): void
    {
        $oMethod = $this->getUserMethod($oUser, $sDriver);
        if (!$oMethod) {
            throw new MFA\Exception\MfaException('That method is not enrolled.');
        }

        if (!$bAllowLastRequired && !$this->userCanRemoveMethod($oUser, $sDriver)) {
            throw new MFA\Exception\MfaException(
                'You cannot remove your last verification method while MFA is required for your account.'
            );
        }

        $oDriver = $this->getDriverBySlug($sDriver);
        $oDriver->reset($oUser, $oMethod);

        /** @var MFA\Model\UserMethod $oModel */
        $oModel = Factory::model('UserMethod', Constants::MODULE_SLUG);
        $oModel->delete((int) $oMethod->id);

        $aRemaining = $this->getUserMethods($oUser);
        if ($oMethod->is_default && !empty($aRemaining)) {
            $oModel->setDefault((int) $oUser->id, (string) $aRemaining[0]->driver);
        }

        $this->oLogger->info(sprintf(
            'Removed MFA method %s for user %s',
            $sDriver,
            $oUser->id
        ));
    }

    // --------------------------------------------------------------------------

    public function setPendingSetup(Token $oToken, string $sDriver, stdClass $oPending): void
    {
        /** @var Encrypt $oEncrypt */
        $oEncrypt = Factory::service('Encrypt');

        $oToken->setData((object) [
            static::TOKEN_DATA_KEY_DRIVER        => $sDriver,
            static::TOKEN_DATA_KEY_PENDING_SETUP => $oEncrypt::encode(json_encode($oPending) ?: '{}'),
        ]);
    }

    // --------------------------------------------------------------------------

    public function getPendingSetup(Token $oToken): ?stdClass
    {
        $sCipher = $oToken->getData(static::TOKEN_DATA_KEY_PENDING_SETUP);
        if (empty($sCipher) || !is_string($sCipher)) {
            return null;
        }

        $sPending = $this->decryptUntrustedValue($sCipher, 'the pending MFA setup payload');

        if ($sPending === null) {
            //  The user restarts setup rather than being shown an error
            return null;
        }

        return (object) json_decode($sPending, false);
    }

    // --------------------------------------------------------------------------

    public function clearPendingSetup(Token $oToken): void
    {
        $oToken->setData((object) [
            static::TOKEN_DATA_KEY_PENDING_SETUP => null,
        ]);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     * @throws MfaException
     */
    public function completeChallenge(Token $oToken, bool $bRememberDevice): string
    {
        /** @var MFA\Model\Token $oTokenModel */
        $oTokenModel = Factory::model('Token', Constants::MODULE_SLUG);
        /** @var Auth\Service\Authentication $oAuthenticationService */
        $oAuthenticationService = Factory::service('Authentication', Auth\Constants::MODULE_SLUG);
        /** @var Auth\Model\User $oUserModel */
        $oUserModel = Factory::model('User', Auth\Constants::MODULE_SLUG);

        $oUser = $oToken->user();
        if ($oUser === null) {
            throw new MfaException('We could not complete your sign-in. Please sign in and try again.');
        }

        $this->setIsPrivileged($oUser, $bRememberDevice);
        if ($oToken->id) {
            $oTokenModel->delete((int) $oToken->id);
        }
        $this->clearTokenCookie();
        $oAuthenticationService->login($oUser);

        if ($oToken->getData(static::TOKEN_DATA_KEY_IS_REMEMBERED)) {
            $oUserModel->setRememberCookie(
                $oUser->id,
                $oUser->password,
                $oUser->email
            );
        }

        return $oToken->getData(static::TOKEN_DATA_KEY_RETURN_TO) ?: siteUrl();
    }

    // --------------------------------------------------------------------------

    /**
     * @throws FactoryException
     */
    public function isPrivileged(): bool
    {
        /** @var Cookie $oCookie */
        $oCookie = Factory::service('Cookie');

        $this->oLogger->info(sprintf(
            'Checking if active user is privileged; active user %s',
            activeUser()->id,
        ));

        $sActiveUserHash      = $this->getIsPrivilegedHash(activeUser());
        $oStoredHashEncrypted = $oCookie->read(static::MFA_COOKIE_IS_PRIVILEGED_KEY);

        if (empty($oStoredHashEncrypted)) {
            return false;
        }

        $sStoredHash = $this->decryptUntrustedValue(
            (string) $oStoredHashEncrypted->value,
            sprintf('the "%s" cookie', static::MFA_COOKIE_IS_PRIVILEGED_KEY)
        );

        if ($sStoredHash === null) {
            //  Discard the unusable cookie so the user is challenged rather than
            //  presented with the same error on every subsequent request
            $this->clearIsPrivilegedCookie();
            return false;
        }

        $bResult = isLoggedIn() && hash_equals($sActiveUserHash, $sStoredHash);

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
                    ? $this->getTrustedDeviceTtl()
                    : null,
                '/',
                '',
                true,
                true,
                'Lax'
            );

        return $this;
    }

    // --------------------------------------------------------------------------

    /**
     * How many MFA tokens a user may have minted in a rolling hour before sign-in
     * is refused; override with the MFA_MAX_TOKEN_MINTS_PER_HOUR config property.
     *
     * A live token is reused rather than counted again (see generateToken()), so
     * this only limits genuinely repeated attempts: the token expiring and being
     * restarted, or the user abandoning and trying again. A ceremony-based driver
     * — a passkey prompt the user can decline, switch devices for, or simply take
     * longer over than typing a code — makes that more likely than the default of
     * 5 comfortably allows for, hence the higher default; it is still far below
     * anything that matters for guessing a code, which registerFailedAttempt()'s
     * five-attempts-per-token cap already covers.
     */
    public function getMaxTokenMintsPerHour(): int
    {
        $iMax = (int) Config::get(
            'MFA_MAX_TOKEN_MINTS_PER_HOUR',
            static::MAX_TOKEN_MINTS_PER_HOUR
        );

        return $iMax > 0
            ? $iMax
            : static::MAX_TOKEN_MINTS_PER_HOUR;
    }

    // --------------------------------------------------------------------------

    /**
     * How long a device stays trusted, in seconds; override with the
     * MFA_TRUSTED_DEVICE_TTL config property.
     */
    public function getTrustedDeviceTtl(): int
    {
        $iTtl = (int) Config::get(
            'MFA_TRUSTED_DEVICE_TTL',
            static::MFA_COOKIE_IS_PRIVILEGED_TTL
        );

        return $iTtl > 0
            ? $iTtl
            : static::MFA_COOKIE_IS_PRIVILEGED_TTL;
    }

    // --------------------------------------------------------------------------

    /**
     * Whether a trusted device stays trusted after the user signs out; override
     * with the MFA_TRUST_SURVIVES_LOGOUT config property.
     */
    public function trustSurvivesLogout(): bool
    {
        return (bool) Config::get('MFA_TRUST_SURVIVES_LOGOUT', false);
    }

    // --------------------------------------------------------------------------

    protected function getIsPrivilegedHash(User $oUser): string
    {
        return sha1(Config::get('PRIVATE_KEY') . $oUser->id . $oUser->salt);
    }
}
