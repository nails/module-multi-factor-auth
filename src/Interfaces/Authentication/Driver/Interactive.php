<?php

namespace Nails\MFA\Interfaces\Authentication\Driver;

use Nails\Auth\Resource\User;
use Nails\MFA\Resource\Token;
use stdClass;

/**
 * Opt-in companion to {@see \Nails\MFA\Interfaces\Authentication\Driver} for
 * drivers that drive the challenge/setup screens themselves (e.g. WebAuthn),
 * rather than asking the user to type a numeric code.
 *
 * The MFA module only ever consults this via an `instanceof` check, so a driver
 * that does not implement it keeps working exactly as before.
 */
interface Interactive
{
    /**
     * Markup rendered inside the verify <form>, in place of (or alongside) the
     * numeric code field. Typically a button that runs a browser ceremony and
     * writes its result into the hidden `code` input before submitting.
     */
    public function getChallengeMarkup(Token $oToken): string;

    /**
     * Markup rendered on the setup-confirm screen, in place of the QR code and
     * secret. `$oPending` is whatever setupStart() returned for this driver.
     */
    public function getSetupMarkup(User $oUser, stdClass $oPending): string;

    /**
     * Loads the driver's front-end assets. Called by the controller immediately
     * after loadStyles() has run its clear(), and regardless of whether the app
     * has overridden the view: the assets are functional, not cosmetic.
     */
    public function loadAssets(): void;

    /**
     * Whether the shared `code` input should be rendered hidden (the driver
     * populates it from script) rather than as a visible numeric field.
     */
    public function hidesCodeInput(): bool;
}
