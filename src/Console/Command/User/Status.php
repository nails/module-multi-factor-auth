<?php

namespace Nails\MFA\Console\Command\User;

use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Service\MultiFactorAuth;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Status extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:user:status')
            ->setDescription('Displays a user\'s MFA policy and enrolled methods')
            ->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'User ID, email, or username; prompted if omitted');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: User Status');

        $oUser = $this->requireUser();

        /** @var MultiFactorAuth $oMfa */
        $oMfa = Factory::service('MultiFactorAuth', Constants::MODULE_SLUG);

        $aLabels = [];
        try {
            foreach ($oMfa->getEnabledDrivers() as $oDriver) {
                $aLabels[$oDriver->getSlug()] = $oDriver->getLabel();
            }
        } catch (MfaException) {
            //  Status should remain useful even if no drivers are enabled
        }

        $oOutput->writeln(sprintf('User: <info>%s</info>', $this->describeUser($oUser)));
        $oOutput->writeln(sprintf(
            'Group policy: <comment>%s</comment>',
            $oMfa->getGroupMode($oUser)
        ));
        $oOutput->writeln(sprintf(
            'Challenge required: <comment>%s</comment>',
            $oMfa->userRequiresChallenge($oUser) ? 'yes' : 'no'
        ));
        $oOutput->writeln('');

        $aMethods = $oMfa->getUserMethods($oUser);
        if (empty($aMethods)) {
            $oOutput->writeln('<comment>No methods enrolled.</comment>');
            return static::EXIT_CODE_SUCCESS;
        }

        (new Table($oOutput))
            ->setHeaders(['Default', 'Method', 'Package', 'Enrolled'])
            ->setRows(array_map(
                static fn($oMethod) => [
                    $oMethod->is_default ? 'yes' : '',
                    $aLabels[$oMethod->driver] ?? 'Unavailable driver',
                    $oMethod->driver,
                    (string) $oMethod->created,
                ],
                $aMethods
            ))
            ->render();

        return static::EXIT_CODE_SUCCESS;
    }
}
