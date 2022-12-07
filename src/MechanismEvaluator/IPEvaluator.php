<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Mechanism\IP;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;
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
