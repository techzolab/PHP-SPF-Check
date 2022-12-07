<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;

class AllEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        return true;
    }
}
