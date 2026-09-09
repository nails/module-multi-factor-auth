<?php

namespace Nails\MFA\Console\Command\User\Method;

use Nails\Common\Exception\NailsException;
use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Service\MultiFactorAuth;
use stdClass;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Add extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:user:method:add')
            ->setDescription('Enrolls a user in an MFA method which requires no interactive setup')
            ->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'User ID, email, or username; prompted if omitted')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption('default', null, InputOption::VALUE_NONE, 'Make this the default method')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Add User Method');

        $oUser   = $this->requireUser();
        $sDriver = $this->requireDriver(
            null,
            $this->enrollableDriverChoices(),
            'Select an MFA driver to enroll',
            'No MFA drivers can be enrolled from the console.'
        )->slug;

        /** @var MultiFactorAuth $oMfa */
        $oMfa    = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);
        $oDriver = $oMfa->getDriverBySlug($sDriver);

        $aEnabled = array_map(
            static fn($oEnabledDriver) => $oEnabledDriver->getSlug(),
            $oMfa->getEnabledDrivers()
        );
        if (!in_array($sDriver, $aEnabled, true)) {
            throw new NailsException(sprintf(
                'MFA driver "%s" is disabled. Enable it before enrolling users.',
                $sDriver
            ));
        }

        if ($oDriver->requiresEnrollment()) {
            throw new NailsException(sprintf(
                '%s requires interactive enrollment. Ask the user to set it up at /mfa/manage.',
                $oDriver->getLabel()
            ));
        }

        if ($oMfa->getUserMethod($oUser, $sDriver)) {
            $oOutput->writeln('<comment>The user is already enrolled in that method.</comment>');
            return static::EXIT_CODE_SUCCESS;
        }

        if (!$this->shouldContinue($oInput, sprintf(
            'Enroll %s in %s?',
            $this->describeUser($oUser),
            $oDriver->getLabel()
        ))) {
            return static::EXIT_CODE_FAILURE;
        }

        $oData = $oDriver->setupComplete($oUser, '', new stdClass());
        $oMfa->enrollMethod(
            $oUser,
            $sDriver,
            $oData,
            (bool) $oInput->getOption('default')
        );

        $oOutput->writeln('<info>User method enrolled.</info>');
        return static::EXIT_CODE_SUCCESS;
    }
}
