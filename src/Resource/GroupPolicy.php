<?php

namespace Nails\MFA\Resource;

use Nails\Auth\Resource\User\Group;
use Nails\Common\Resource;
use Nails\MFA\Model\GroupPolicy as GroupPolicyModel;

class GroupPolicy extends Resource\Entity
{
    public ?int    $group_id = null;
    public ?Group  $group    = null;
    public string  $mode     = GroupPolicyModel::MODE_DISABLED;
}
