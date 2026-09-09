<?php

namespace Nails\MFA\Console\Command\Driver;

use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Service\AuthenticationDriver;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Enable extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:driver:enable')
            ->setDescription('Enables an installed MFA driver')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Enable Driver');

        $sSlug = $this->requireDriver(
            null,
            $this->disabledDriverChoices(),
            'Select an MFA driver to enable',
            'All installed MFA drivers are already enabled.'
        )->slug;

        /** @var AuthenticationDriver $oService */
        $oService = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oService->getEnabledSlug();

        if (in_array($sSlug, $aEnabled, true)) {
            $oOutput->writeln(sprintf('<comment>%s is already enabled.</comment>', $sSlug));
            return static::EXIT_CODE_SUCCESS;
        }

        if (!$this->shouldContinue($oInput, sprintf('Enable MFA driver "%s"?', $sSlug))) {
            return static::EXIT_CODE_FAILURE;
        }

        $aEnabled[] = $sSlug;
        $oService->saveEnabled($aEnabled);

        $oOutput->writeln(sprintf('<info>Enabled %s.</info>', $sSlug));
        return static::EXIT_CODE_SUCCESS;
    }
}
