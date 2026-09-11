<?php

namespace Nails\MFA\Interfaces\Authentication;

use Nails\Auth\Resource\User;
use Nails\Common\Service\UserFeedback;
use Nails\MFA\Resource\Token;
use Nails\MFA\Resource\UserMethod;
use stdClass;

/**
 * @method string getSlug() Provided by Nails\Common\Driver\Base on every concrete driver
 */
interface Driver
{
    public function getLabel(): string;

    public function getDescription(): string;

    public function getSetupDescription(): string;

    public function preForm(Token $oToken, UserFeedback $oUserFeedback): void;

    public function postForm(Token $oToken): void;

    public function validate(Token $oToken, string $sCode): void;

    public function canTryAgain(): bool;

    /**
     * Issues a replacement code for an in-progress challenge; only ever called
     * on drivers which report canTryAgain().
     */
    public function resend(Token $oToken, UserFeedback $oUserFeedback): void;

    public function requiresEnrollment(): bool;

    public function setupStart(User $oUser): stdClass;

    public function setupComplete(User $oUser, string $sCode, stdClass $oPending): stdClass;

    public function reset(User $oUser, UserMethod $oMethod): void;
}
