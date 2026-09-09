<?php

namespace Nails\MFA\Console\Command\User\Method;

use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Service\MultiFactorAuth;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Remove extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:user:method:remove')
            ->setDescription('Removes an enrolled MFA method from a user')
            ->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'User ID, email, or username; prompted if omitted')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Do not ask for confirmation; also permits removing the last required method'
            );
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Remove User Method');

        $oUser   = $this->requireUser();
        $sDriver = $this->requireDriver(
            null,
            $this->enrolledDriverChoices($oUser),
            'Select an enrolled MFA method to remove',
            'The user has no enrolled MFA methods.'
        )->slug;

        /** @var MultiFactorAuth $oMfa */
        $oMfa = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);

        if (!$oMfa->getUserMethod($oUser, $sDriver)) {
            $oOutput->writeln('<comment>The user is not enrolled in that method.</comment>');
            return static::EXIT_CODE_SUCCESS;
        }

        if (!$this->shouldContinue($oInput, sprintf(
            'Remove MFA method "%s" from %s?',
            $sDriver,
            $this->describeUser($oUser)
        ))) {
            return static::EXIT_CODE_FAILURE;
        }

        $oMfa->removeMethod(
            $oUser,
            $sDriver,
            (bool) $oInput->getOption('force')
        );

        $oOutput->writeln('<info>User method removed.</info>');
        return static::EXIT_CODE_SUCCESS;
    }
}
