<?php

namespace Nails\MFA\Console\Command\Driver;

use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Service\AuthenticationDriver;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Disable extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:driver:disable')
            ->setDescription('Disables an MFA driver without deleting user enrollments')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Do not ask for confirmation; also permits disabling the last driver'
            );
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Disable Driver');

        $sSlug = $this->requireDriver(
            null,
            $this->enabledDriverChoices(),
            'Select an MFA driver to disable',
            'No MFA drivers are currently enabled.'
        )->slug;

        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oService->getEnabledSlug();

        if (!in_array($sSlug, $aEnabled, true)) {
            $oOutput->writeln(sprintf('<comment>%s is already disabled.</comment>', $sSlug));
            return static::EXIT_CODE_SUCCESS;
        }

        if (count($aEnabled) === 1 && !$oInput->getOption('force')) {
            $this->error([
                'Refusing to disable the last enabled MFA driver.',
                'Required users would be unable to sign in.',
                'Use --force only if this is intentional.',
            ]);
            return static::EXIT_CODE_FAILURE;
        }

        if (!$this->shouldContinue(
            $oInput,
            sprintf('Disable MFA driver "%s"? Existing enrollments will be retained.', $sSlug)
        )) {
            return static::EXIT_CODE_FAILURE;
        }

        $oService->saveEnabled(array_values(array_diff($aEnabled, [$sSlug])));

        $oOutput->writeln(sprintf('<info>Disabled %s.</info>', $sSlug));
        return static::EXIT_CODE_SUCCESS;
    }
}
