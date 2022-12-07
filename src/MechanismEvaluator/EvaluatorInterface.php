<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\DNS\Session;
use Nzldev\ToolsSPFCheck\Enum\Mechanism;
use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;
use Nzldev\ToolsSPFCheck\ToolsSPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

interface EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool;
}
