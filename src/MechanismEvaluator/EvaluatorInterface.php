<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\DNS\Session;
use Nzldev\SPFCheck\Enum\Mechanism;
use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;
use Nzldev\SPFCheck\SPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

interface EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool;
}
