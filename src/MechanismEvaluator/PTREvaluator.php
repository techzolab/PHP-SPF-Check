<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Mechanism\PTR;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;

class PTREvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if (!$mechanism instanceof PTR) {
            throw new \LogicException();
        }

        $ptrRecords = $result->getDNSSession()->resolvePTR($query->getIpAddress());
        foreach ($ptrRecords as $ptrRecord) {
            if (str_ends_with(strtolower($ptrRecord), strtolower($mechanism->getHostname()))) {
                return true;
            }
        }

        return false;
    }
}
