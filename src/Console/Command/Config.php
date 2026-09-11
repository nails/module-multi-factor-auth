<?php

namespace Nails\MFA\Console\Command;

use Nails\Auth;
use Nails\Factory;
use Nails\MFA\Constants;
use Nails\MFA\Model\GroupPolicy;
use Nails\MFA\Service\AuthenticationDriver;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Config extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:config')
            ->setDescription('Displays MFA drivers, app settings, and group policies');
    }

    // --------------------------------------------------------------------------

    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Configuration');

        /** @var AuthenticationDriver $oDrivers */
        $oDrivers = Factory::service('AuthenticationDriver', Constants::MODULE_SLUG);
        $aEnabled = (array) $oDrivers->getEnabledSlug();

        $oOutput->writeln('<info>Drivers</info>');
        (new Table($oOutput))
            ->setHeaders(['Status', 'Driver', 'Package'])
            ->setRows(array_map(
                static fn($oComponent) => [
                    in_array($oComponent->slug, $aEnabled, true) ? 'enabled' : 'disabled',
                    $oComponent->name,
                    $oComponent->slug,
                ],
                $oDrivers->getAll()
            ))
            ->render();

        /** @var Auth\Model\User\Group $oGroups */
        $oGroups = Factory::model('UserGroup', Auth\Constants::MODULE_SLUG);
        /** @var GroupPolicy $oPolicies */
        $oPolicies = Factory::model('GroupPolicy', Constants::MODULE_SLUG);

        $aGroupRows = [];
        foreach ($oGroups->getAll() as $oGroup) {
            /** @var Auth\Resource\User\Group $oGroup */
            $aGroupRows[] = [
                (string) $oGroup->id,
                (string) $oGroup->label,
                (string) $oGroup->slug,
                $oPolicies->getModeForGroup((int) $oGroup->id),
            ];
        }

        $oOutput->writeln('');
        $oOutput->writeln('<info>Group policies</info>');
        (new Table($oOutput))
            ->setHeaders(['ID', 'Group', 'Slug', 'Policy'])
            ->setRows($aGroupRows)
            ->render();

        $oOutput->writeln('');
        return static::EXIT_CODE_SUCCESS;
    }
}
