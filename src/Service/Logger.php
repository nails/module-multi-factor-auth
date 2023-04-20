<?php

namespace Nails\MFA\Service;

use Nails\Common\Factory;

class Logger
{
    private Factory\Logger $oLogger;

    // --------------------------------------------------------------------------

    public function __construct(Factory\Logger $oLogger = null)
    {
        if ($oLogger) {
            $this->oLogger = $oLogger;

        } else {
            /** @var \DateTime $oNow */
            $oNow = \Nails\Factory::factory('DateTime');

            $this->oLogger = \Nails\Factory::factory('Logger');
            $this->oLogger
                ->setFile('mfa-' . $oNow->format('Y-m-d') . '.php')
                //  Set a uniqid() to more easily filter logs by session
                ->setFormat('%s [' . uniqid() . '] - %s --> %s ');
        }
    }

    // --------------------------------------------------------------------------

    public function debug(string $sLine = ''): self
    {
        $this->oLogger->debug($sLine);
        return $this;
    }

    // --------------------------------------------------------------------------

    public function info(string $sLine = ''): self
    {
        $this->oLogger->info($sLine);
        return $this;
    }

    // --------------------------------------------------------------------------

    public function warning(string $sLine = ''): self
    {
        $this->oLogger->warning($sLine);
        return $this;
    }

    // --------------------------------------------------------------------------

    public function error(string $sLine = ''): self
    {
        $this->oLogger->error($sLine);
        return $this;
    }
}