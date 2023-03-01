<?php

namespace Nails\MFA\Interfaces\Authentication;

use Nails\Common\Service\UserFeedback;
use Nails\MFA\Resource\Token;

interface Driver
{
    public function getLabel(): string;

    public function getDescription(): string;

    public function preForm(Token $oToken, UserFeedback $oUserFeedback): void;

    public function postForm(Token $oToken): void;

    public function validate(Token $oToken, string $sCode): void;

    public function canTryAgain(): bool;
}
