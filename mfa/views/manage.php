<?php

/**
 * @var \Nails\Auth\Resource\User $oUser
 * @var string $sGroupMode
 * @var \Nails\MFA\Resource\UserMethod[] $aMethods
 * @var \Nails\MFA\Interfaces\Authentication\Driver[] $aSetupDrivers
 * @var object|null $oPending
 * @var \Nails\MFA\Interfaces\Authentication\Driver|null $oPendingDriver
 * @var array<string, string> $aDriverLabels
 * @var array<string, bool> $aCanRemove
 * @var string|null $sReturnUrl
 */

use Nails\Common\Service\View;
use Nails\Factory;
use Nails\MFA\Interfaces\Authentication\Driver\FormFragment;
use Nails\MFA\Model\GroupPolicy;

/** @var View $oView */
$oView = Factory::service('View');

?>
<div class="mfa container container-md py-xl">
    <h1 class="text-center">Two-factor authentication</h1>
    <p class="text-muted text-center">
        Verification methods ask you to confirm your identity when you sign in, in addition to your password.
        <?php

        echo $sGroupMode === GroupPolicy::MODE_REQUIRED
            ? 'Your account requires at least one method.'
            : 'They are optional for your account.';

        ?>
    </p>
    <?php

    $oView->load('auth/_components/alerts');

    if ($oPending) {

        $sPendingLabel = $aDriverLabels[$oPending->driver] ?? $oPending->driver;
        $oPendingData  = (object) $oPending->pending;
        $bFormFragment = isset($oPendingDriver) && $oPendingDriver instanceof FormFragment;
        $bHideCode     = $bFormFragment && $oPendingDriver->hidesCodeInput();

        ?>
        <div class="panel panel--primary">
            <div class="panel__header">
                <h2 class="panel__title">
                    Finish setting up <?=htmlspecialchars((string) $sPendingLabel)?>
                </h2>
            </div>
            <?=form_open(null, 'class="form mb-0"')?>
            <?php if ($sReturnUrl) { ?>
                <input type="hidden" name="return" value="<?=htmlspecialchars($sReturnUrl, ENT_QUOTES)?>">
            <?php } ?>
            <div class="panel__body">
                <?php

                if ($bFormFragment) {
                    //  See mfa/views/form.php: the driver JS locates this via
                    //  [name="action"] and sets it before a programmatic
                    //  form.submit(), which carries no button's name/value on its own.
                    ?>
                    <input type="hidden" name="action" value="">
                    <?php
                    echo $oPendingDriver->getSetupMarkup($oUser, $oPendingData);
                } else {
                    if (!empty($oPendingData->qr_svg)) {
                        ?>
                        <p class="text-center">
                            <?=$oPendingData->qr_svg?>
                        </p>
                        <?php
                    }
                    if (!empty($oPendingData->secret)) {
                        ?>
                        <p class="text-center">
                            <code><?=htmlspecialchars((string) $oPendingData->secret)?></code>
                            <small class="form__help">Enter this secret manually if you cannot scan the code</small>
                        </p>
                        <?php
                    }
                }

                if ($bHideCode) {
                    ?>
                    <input type="hidden" name="code" id="input-code" value="">
                    <?php
                } else {
                    ?>
                    <div class="form__group">
                        <label class="form__label" for="input-code">Code</label>
                        <?=form_input('code', '', 'id="input-code" autocomplete="one-time-code" inputmode="numeric" class="form__control"')?>
                        <small class="form__help">
                            Enter the code from <?=htmlspecialchars((string) $sPendingLabel)?> to confirm setup.
                        </small>
                    </div>
                    <?php
                }

                ?>
            </div>
            <div class="panel__footer">
                <div class="form__actions">
                    <?php if (!$bHideCode) { ?>
                        <button type="submit" name="action" value="setup_confirm" class="btn btn--primary">
                            Confirm
                        </button>
                    <?php } ?>
                    <button type="submit" name="action" value="setup_cancel" class="btn btn--secondary">
                        Cancel
                    </button>
                </div>
            </div>
            <?=form_close()?>
        </div>
        <?php
    }

    ?>
    <div class="panel">
        <div class="panel__header">
            <h2 class="panel__title">Your methods</h2>
        </div>
        <div class="panel__body">
            <?php

            if (empty($aMethods)) {
                ?>
                <p class="text-muted">You have not set up any verification methods yet.</p>
                <?php

            } else {
                ?>
                <ul class="list list--unstyled list--divided">
                    <?php

                    foreach ($aMethods as $oMethod) {

                        $sDriver     = (string) $oMethod->driver;
                        $bCanRemove  = !empty($aCanRemove[$sDriver]);
                        $bHasActions = $bCanRemove || !$oMethod->is_default;

                        ?>
                        <li class="d-flex justify-content-between align-items-center">
                            <strong class="mr-md">
                                <?=htmlspecialchars($aDriverLabels[$sDriver] ?? $sDriver)?>
                            </strong>
                            <span class="d-flex align-items-center">
                                <?php if ($oMethod->is_default) { ?>
                                    <small class="text-muted mr-md">Used by default</small>
                                <?php } ?>
                                <?php

                                if ($bHasActions) {

                                    echo form_open(null, 'class="form mb-0"');
                                    ?>
                                    <input type="hidden" name="driver" value="<?=htmlspecialchars($sDriver)?>">
                                    <?php if ($sReturnUrl) { ?>
                                        <input type="hidden" name="return" value="<?=htmlspecialchars($sReturnUrl, ENT_QUOTES)?>">
                                    <?php } ?>
                                    <span class="form__actions mb-0 px-0">
                                        <?php if (!$oMethod->is_default) { ?>
                                            <button type="submit" name="action" value="set_default" class="btn btn--sm btn--secondary">
                                                Make default
                                            </button>
                                        <?php } ?>
                                        <?php if ($bCanRemove) { ?>
                                            <button type="submit" name="action" value="remove" class="btn btn--sm btn--outline-danger" onclick="return confirm('Remove this verification method?');">
                                                Remove
                                            </button>
                                        <?php } ?>
                                    </span>
                                    <?php
                                    echo form_close();
                                }

                                ?>
                            </span>
                        </li>
                        <?php
                    }

                    ?>
                </ul>
                <?php
            }

            ?>
        </div>
        <?php if (!empty($aMethods) && in_array(false, $aCanRemove, true)) { ?>
            <div class="panel__footer">
                <small class="text-muted">
                    Your last method cannot be removed while your account requires two-factor authentication.
                </small>
            </div>
        <?php } ?>
    </div>
    <?php

    if (!empty($aSetupDrivers) && !$oPending) {
        ?>
        <div class="panel">
            <div class="panel__header">
                <h2 class="panel__title">Add a method</h2>
            </div>
            <div class="panel__body">
                <ul class="list list--unstyled list--divided">
                    <?php

                    foreach ($aSetupDrivers as $oDriver) {
                        ?>
                        <li class="d-flex justify-content-between align-items-center">
                            <span class="mr-md">
                                <strong><?=htmlspecialchars($oDriver->getLabel())?></strong>
                                <small class="form__help"><?=htmlspecialchars($oDriver->getSetupDescription())?></small>
                            </span>
                            <?php

                            echo form_open(null, 'class="form mb-0"');
                            ?>
                            <input type="hidden" name="driver" value="<?=htmlspecialchars((string) $oDriver->getSlug())?>">
                            <?php if ($sReturnUrl) { ?>
                                <input type="hidden" name="return" value="<?=htmlspecialchars($sReturnUrl, ENT_QUOTES)?>">
                            <?php } ?>
                            <button type="submit" name="action" value="setup_choose" class="btn btn--sm btn--primary">
                                Add
                            </button>
                            <?php
                            echo form_close();

                            ?>
                        </li>
                        <?php
                    }

                    ?>
                </ul>
            </div>
        </div>
        <?php
    }

    if ($sReturnUrl) {
        ?>
        <div class="form__actions">
            <a href="<?=htmlspecialchars($sReturnUrl, ENT_QUOTES)?>" class="btn btn--secondary">
                Back
            </a>
        </div>
        <?php
    }

    ?>
</div>
