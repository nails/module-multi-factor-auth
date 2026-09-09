<?php

namespace Nails\MFA\Console\Command\Driver;

use JsonException;
use Nails\Common\Exception\NailsException;
use Nails\MFA\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Setting extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('mfa:driver:setting')
            ->setDescription('Lists or updates app settings for an MFA driver')
            ->addOption('driver', 'd', InputOption::VALUE_REQUIRED, 'Composer package slug; prompted if omitted')
            ->addOption('key', 'k', InputOption::VALUE_OPTIONAL, 'Setting key')
            ->addOption('value', null, InputOption::VALUE_OPTIONAL, 'New setting value')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Decode the value as JSON')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    // --------------------------------------------------------------------------

    /**
     * @throws JsonException
     * @throws NailsException
     */
    protected function execute(InputInterface $oInput, OutputInterface $oOutput): int
    {
        parent::execute($oInput, $oOutput);
        $this->banner('MFA: Driver Setting');

        $sDriver = $this->requireDriver()->slug;

        $sKey   = $oInput->getOption('key');
        $mValue = $oInput->getOption('value');

        if ($sKey === null || $sKey === '') {
            $aSettings = appSetting(null, $sDriver, []);
            if (empty($aSettings)) {
                $oOutput->writeln('<comment>No app settings have been saved for this driver.</comment>');
                return static::EXIT_CODE_SUCCESS;
            }

            (new Table($oOutput))
                ->setHeaders(['Key', 'Value'])
                ->setRows(array_map(
                    static fn($sSetting, $mSettingValue) => [
                        $sSetting,
                        is_scalar($mSettingValue) || $mSettingValue === null
                            ? json_encode($mSettingValue)
                            : json_encode($mSettingValue, JSON_PRETTY_PRINT),
                    ],
                    array_keys($aSettings),
                    array_values($aSettings)
                ))
                ->render();
            return static::EXIT_CODE_SUCCESS;
        }

        if ($mValue === null) {
            $mCurrent = appSetting((string) $sKey, $sDriver);
            $oOutput->writeln(sprintf(
                '<info>%s</info> = %s',
                $sKey,
                json_encode($mCurrent, JSON_PRETTY_PRINT)
            ));
            return static::EXIT_CODE_SUCCESS;
        }

        if ($oInput->getOption('json')) {
            $mValue = json_decode((string) $mValue, true, 512, JSON_THROW_ON_ERROR);
        }

        if (!$this->shouldContinue(
            $oInput,
            sprintf('Set %s:%s to %s?', $sDriver, $sKey, json_encode($mValue))
        )) {
            return static::EXIT_CODE_FAILURE;
        }

        if (!setAppSetting((string) $sKey, $sDriver, $mValue)) {
            throw new NailsException('Failed to save the driver setting.');
        }

        $oOutput->writeln('<info>Driver setting saved.</info>');
        return static::EXIT_CODE_SUCCESS;
    }
}
