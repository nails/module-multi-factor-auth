<?php

namespace Nails\MFA\Console\Command;

use Nails\Auth;
use Nails\Auth\Resource\User;
use Nails\Common\Exception\NailsException;
use Nails\Common\Factory\Component;
use Nails\Console\Command\Base;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Service\AuthenticationDriver;
use Nails\MFA\Service\MultiFactorAuth;
use Symfony\Component\Console\Input\InputInterface;

abstract class Command extends Base
{
    protected function optionString(string $sOption): string
    {
        return trim((string) $this->oInput->getOption($sOption));
    }

    // --------------------------------------------------------------------------

    protected function canPrompt(): bool
    {
        if (!$this->oInput->isInteractive()) {
            return false;
        }

        return !$this->oInput->hasOption('force')
            || !$this->oInput->getOption('force');
    }

    // --------------------------------------------------------------------------

    /**
     * Asks the user to pick from a keyed list of choices, returning the key
     *
     * Symfony returns the label when the choices are a list, and the key when they
     * are associative, so normalise to a list and map the answer back to its key.
     *
     * @param array<string, string> $aChoices
     * @throws NailsException
     */
    protected function chooseKey(string $sQuestion, array $aChoices): string
    {
        $aKeys   = array_keys($aChoices);
        $aLabels = array_values($aChoices);

        $sAnswer = (string) $this->choose($sQuestion, $aLabels);
        $mIndex  = array_search($sAnswer, $aLabels, true);

        if ($mIndex !== false) {
            return (string) $aKeys[$mIndex];
        }

        if (array_key_exists($sAnswer, $aChoices)) {
            return $sAnswer;
        }

        throw new NailsException(sprintf('"%s" is not a valid choice.', $sAnswer));
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     */
    protected function requireUser(?string $sIdentifier = null): User
    {
        $sIdentifier = trim((string) ($sIdentifier ?? $this->optionString('user')));

        if ($sIdentifier === '') {
            if (!$this->canPrompt()) {
                throw new NailsException('A user is required; use --user=<id, email, or username>.');
            }

            $sIdentifier = trim((string) $this->ask('User ID, email, or username', ''));
        }

        if ($sIdentifier === '') {
            throw new NailsException('A user is required; use --user=<id, email, or username>.');
        }

        return $this->resolveUser($sIdentifier);
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     */
    protected function requireGroup(?string $sIdentifier = null): Auth\Resource\User\Group
    {
        $sIdentifier = trim((string) ($sIdentifier ?? $this->optionString('group')));

        if ($sIdentifier === '') {
            $aChoices = $this->groupChoices();
            if (!$this->canPrompt()) {
                throw new NailsException('A group is required; use --group=<id or slug>.');
            }
            if (empty($aChoices)) {
                throw new NailsException('No user groups are available.');
            }

            $sIdentifier = $this->chooseKey('Select a user group', $aChoices);
        }

        return $this->resolveGroup($sIdentifier);
    }

    // --------------------------------------------------------------------------

    /**
     * @param array<string, string>|null $aChoices
     * @throws NailsException
     */
    protected function requireDriver(
        ?string $sSlug = null,
        ?array $aChoices = null,
        string $sQuestion = 'Select an MFA driver',
        string $sEmptyMessage = 'No MFA drivers are available.'
    ): Component {
        $sSlug    = trim((string) ($sSlug ?? $this->optionString('driver')));
        $aChoices = $aChoices ?? $this->driverChoices();

        if ($sSlug === '') {
            if (!$this->canPrompt()) {
                throw new NailsException('A driver is required; use --driver=<package>.');
            }
            if (empty($aChoices)) {
                throw new NailsException($sEmptyMessage);
            }

            $sSlug = $this->chooseKey($sQuestion, $aChoices);
        }

        return $this->resolveDriver($sSlug);
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function driverChoices(?callable $fnFilter = null): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aChoices = [];

        foreach ($oService->getAll() as $oComponent) {
            if ($fnFilter && !$fnFilter($oComponent, $oService)) {
                continue;
            }

            $aChoices[$oComponent->slug] = sprintf(
                '%s (%s)',
                $this->driverLabel($oComponent),
                $oComponent->slug
            );
        }

        return $aChoices;
    }

    // --------------------------------------------------------------------------

    protected function driverLabel(Component $oComponent): string
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);

        try {
            $sLabel = (string) $oService->getInstance($oComponent)?->getLabel();
        } catch (NailsException) {
            $sLabel = '';
        }

        return $sLabel ?: (string) $oComponent->name;
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function enabledDriverChoices(): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oService->getEnabledSlug();

        return $this->driverChoices(
            static fn(Component $oComponent) => in_array($oComponent->slug, $aEnabled, true)
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function disabledDriverChoices(): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oService->getEnabledSlug();

        return $this->driverChoices(
            static fn(Component $oComponent) => !in_array($oComponent->slug, $aEnabled, true)
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function enrollableDriverChoices(): array
    {
        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oService->getEnabledSlug();

        return $this->driverChoices(static function (Component $oComponent) use ($oService, $aEnabled) {
            if (!in_array($oComponent->slug, $aEnabled, true)) {
                return false;
            }

            $oDriver = $oService->getInstance($oComponent);

            return $oDriver && !$oDriver->requiresEnrollment();
        });
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function enrolledDriverChoices(User $oUser): array
    {
        /** @var MultiFactorAuth $oMfa */
        $oMfa     = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        $aChoices = [];

        foreach ($oMfa->getUserMethods($oUser) as $oMethod) {
            $sSlug  = (string) $oMethod->driver;
            $sLabel = $sSlug;

            try {
                $sLabel = sprintf(
                    '%s (%s)',
                    $oMfa->getDriverBySlug($sSlug)->getLabel(),
                    $sSlug
                );
            } catch (MfaException) {
                $sLabel = sprintf('%s (unavailable)', $sSlug);
            }

            $aChoices[$sSlug] = $sLabel;
        }

        return $aChoices;
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, string>
     */
    protected function groupChoices(): array
    {
        /** @var Auth\Model\User\Group $oModel */
        $oModel   = Factory::model('UserGroup', Auth\Constants::MODULE_SLUG);
        $aChoices = [];

        foreach ($oModel->getAll() as $oGroup) {
            $sKey            = trim((string) $oGroup->slug) ?: (string) $oGroup->id;
            $aChoices[$sKey] = sprintf(
                '%s (%s)',
                $oGroup->label,
                $oGroup->slug
            );
        }

        return $aChoices;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     */
    protected function resolveUser(string $sIdentifier): User
    {
        $sIdentifier = trim($sIdentifier);
        if ($sIdentifier === '') {
            throw new NailsException('A user is required; use --user=<id, email, or username>.');
        }

        /** @var Auth\Model\User $oModel */
        $oModel = Factory::model('User', Auth\Constants::MODULE_SLUG);

        if (is_numeric($sIdentifier)) {
            $oUser = $oModel->getById((int) $sIdentifier);
        } else {
            $oUser = $oModel->getByEmail($sIdentifier)
                ?: $oModel->getByUsername($sIdentifier);
        }

        if (!$oUser) {
            throw new NailsException(sprintf(
                'Could not find a user by ID, email, or username "%s".',
                $sIdentifier
            ));
        }

        return $oUser;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     */
    protected function resolveGroup(string $sIdentifier): Auth\Resource\User\Group
    {
        $sIdentifier = trim($sIdentifier);
        if ($sIdentifier === '') {
            throw new NailsException('A group is required; use --group=<id or slug>.');
        }

        /** @var Auth\Model\User\Group $oModel */
        $oModel = Factory::model('UserGroup', Auth\Constants::MODULE_SLUG);
        $oGroup = $oModel->getByIdOrSlug($sIdentifier);

        if (!$oGroup) {
            throw new NailsException(sprintf(
                'Could not find a user group by ID or slug "%s".',
                $sIdentifier
            ));
        }

        return $oGroup;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws NailsException
     */
    protected function resolveDriver(string $sSlug): Component
    {
        $sSlug = trim($sSlug);
        if ($sSlug === '') {
            throw new NailsException('A driver is required; use --driver=<package>.');
        }

        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $oDriver  = $oService->getBySlug($sSlug);

        if (!$oDriver) {
            throw new NailsException(sprintf(
                'MFA driver "%s" is not installed.',
                $sSlug
            ));
        }

        return $oDriver;
    }

    // --------------------------------------------------------------------------

    protected function shouldContinue(InputInterface $oInput, string $sQuestion): bool
    {
        return (bool) $oInput->getOption('force')
            || $this->confirm($sQuestion, false);
    }

    // --------------------------------------------------------------------------

    protected function describeUser(User $oUser): string
    {
        return sprintf(
            '#%s %s (%s)',
            $oUser->id,
            trim((string) $oUser->name),
            $oUser->email
        );
    }
}
