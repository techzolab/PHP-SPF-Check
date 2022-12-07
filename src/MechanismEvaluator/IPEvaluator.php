<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Mechanism\IP;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;
use Symfony\Component\HttpFoundation\IpUtils;

class IPEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if (!$mechanism instanceof IP) {
            throw new \LogicException();
        }

        return IpUtils::checkIp($query->getIpAddress(), $mechanism->getNetwork() . '/' . $mechanism->getCidr());
    }
}
