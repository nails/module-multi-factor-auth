<?php

/**
 * Navigation shared by every MFA driver challenge.
 *
 * Drivers provide only their challenge UI; choosing another method and
 * cancelling belong to the MFA flow itself.
 *
 * @var \Nails\MFA\Interfaces\Authentication\Driver[] $aOtherMethods
 * @var bool                                           $bCanChooseAnother
 * @var bool                                           $bIsSetup
 */

$aOtherMethods      = $aOtherMethods ?? [];
$bCanChooseAnother  = $bCanChooseAnother ?? false;
$bIsSetup           = $bIsSetup ?? false;

?>
<div class="form__actions form__actions--stacked">
    <?php

    /**
     * Falling back to an enrolled method and setting a different one up are both
     * ways out of a challenge the user cannot complete, and they are not
     * alternatives to each other: a user part way through setup may still have
     * something enrolled to fall back on, and a user whose only enrolled method
     * is refusing them has nothing but setup left. Offer whichever apply.
     */

    if (!empty($aOtherMethods) || $bCanChooseAnother) {
        ?>
        <p class="text-center"><strong>Choose another method</strong></p>
        <?php
    }

    foreach ($aOtherMethods as $oOther) {
        echo form_open(null, 'class="form"');
        ?>
        <input type="hidden" name="driver" value="<?=htmlspecialchars((string) $oOther->getSlug())?>">
        <button type="submit" name="action" value="switch" class="btn btn--block btn--secondary">
            Use <?=htmlspecialchars($oOther->getLabel())?>
        </button>
        <?php
        echo form_close();
    }

    if ($bCanChooseAnother) {
        echo form_open(null, 'class="form"');
        ?>
        <button type="submit" name="action" value="setup_back" class="btn btn--block btn--secondary">
            Set up a different method
        </button>
        <?php
        echo form_close();
    }

    echo form_open(null, 'class="form"');
    ?>
    <button
        type="submit"
        name="action"
        value="<?=$bIsSetup ? 'setup_cancel' : 'cancel'?>"
        class="btn btn--block btn--link"
    >
        <?=$bIsSetup ? 'Cancel setup' : 'Cancel sign in'?>
    </button>
    <?php
    echo form_close();

    ?>
</div>
