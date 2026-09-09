<?php

namespace Nails\MFA\Console\Command\User\Method;

use Nails\Common\Exception\NailsException;
use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Service\MultiFactorAuth;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class DefaultMethod extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:user:method:default')
            ->setDescription('Changes a user\'s default enrolled MFA method')
            ->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'User ID, email, or username; prompted if omitted')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Set Default User Method');

        $oUser   = $this->requireUser();
        $sDriver = $this->requireDriver(
            null,
            $this->enrolledDriverChoices($oUser),
            'Select the default MFA method',
            'The user has no enrolled MFA methods.'
        )->slug;

        /** @var MultiFactorAuth $oMfa */
        $oMfa     = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        $oCurrent = $oMfa->getDefaultUserMethod($oUser);

        $aEnabled = array_map(
            static fn($oEnabledDriver) => $oEnabledDriver->getSlug(),
            $oMfa->getEnabledDrivers()
        );
        if (!in_array($sDriver, $aEnabled, true)) {
            throw new NailsException(sprintf(
                'MFA driver "%s" is disabled and cannot be made the default.',
                $sDriver
            ));
        }

        if ($oCurrent?->driver === $sDriver) {
            $oOutput->writeln('<comment>That method is already the default.</comment>');
            return static::EXIT_CODE_SUCCESS;
        }

        if (!$this->shouldContinue($oInput, sprintf(
            'Set "%s" as the default MFA method for %s?',
            $sDriver,
            $this->describeUser($oUser)
        ))) {
            return static::EXIT_CODE_FAILURE;
        }

        $oMfa->setDefaultMethod($oUser, $sDriver);

        $oOutput->writeln('<info>Default user method updated.</info>');
        return static::EXIT_CODE_SUCCESS;
    }
}
