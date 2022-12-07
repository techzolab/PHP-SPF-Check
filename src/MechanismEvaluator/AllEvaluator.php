<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;

class AllEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        return true;
    }
}
