<?php

namespace Nails\MFA\Console\Command\Group;

use Nails\Common\Exception\NailsException;
use Nails\Factory;
use Nails\MFA\Console\Command\Command;
use Nails\MFA\Constants;
use Nails\MFA\Model\GroupPolicy as GroupPolicyModel;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Policy extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:group:policy')
            ->setDescription('Shows or changes the MFA policy for a user group')
            ->addOption('group', 'g', InputOption::VALUE_REQUIRED, 'Group ID or slug; prompted if omitted')
            ->addOption(
                'mode',
                'm',
                InputOption::VALUE_OPTIONAL,
                'Policy: DISABLED, OPTIONAL, or REQUIRED'
            )
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Group Policy');

        $oGroup = $this->requireGroup();

        /** @var GroupPolicyModel $oModel */
        $oModel       = Factory::model('GroupPolicy', Constants::MODULE_SLUG);
        $sCurrentMode = $oModel->getModeForGroup((int) $oGroup->id);
        $sNewMode     = strtoupper(trim((string) $oInput->getOption('mode')));

        if ($sNewMode === '') {
            $oOutput->writeln(sprintf(
                '<info>%s</info> (%s): <comment>%s</comment>',
                $oGroup->label,
                $oGroup->slug,
                $sCurrentMode
            ));
            return static::EXIT_CODE_SUCCESS;
        }

        if (!array_key_exists($sNewMode, GroupPolicyModel::modes())) {
            throw new NailsException(sprintf(
                'Invalid mode "%s". Expected one of: %s.',
                $sNewMode,
                implode(', ', array_keys(GroupPolicyModel::modes()))
            ));
        }

        if ($sCurrentMode === $sNewMode) {
            $oOutput->writeln('<comment>The group already uses that MFA policy.</comment>');
            return static::EXIT_CODE_SUCCESS;
        }

        if (!$this->shouldContinue($oInput, sprintf(
            'Change MFA policy for "%s" from %s to %s?',
            $oGroup->label,
            $sCurrentMode,
            $sNewMode
        ))) {
            return static::EXIT_CODE_FAILURE;
        }

        $oModel->setModeForGroup((int) $oGroup->id, $sNewMode);
        $oOutput->writeln('<info>Group MFA policy updated.</info>');

        return static::EXIT_CODE_SUCCESS;
    }
}
