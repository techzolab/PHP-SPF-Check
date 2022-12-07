<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Mechanism\PTR;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;

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
