<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\Exception\PermErrorException;
use Nzldev\SPFCheck\Exception\TempErrorException;
use Nzldev\SPFCheck\MacroUtils;
use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Mechanism\IncludeMechanism;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;

class IncludeEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result, callable $doGetResult = null): bool
    {
        if (!$mechanism instanceof IncludeMechanism) {
            throw new \LogicException();
        }
        if (!$doGetResult) {
            throw new \LogicException();
        }

        $result->getDNSSession()->countRedirect();

        $hostname = $mechanism->getHostname();
        $hostname = MacroUtils::expandMacro($hostname, $query, $result->getDNSSession(), false);
        $hostname = MacroUtils::truncateDomainName($hostname);

        $includeQuery = $query->createRedirectedQuery($hostname);
        $includeResult = $doGetResult($includeQuery, $result);
        switch ($includeResult->getResult()) {
            case Result::PASS:
                return true;
            case Result::FAIL:
            case Result::SOFTFAIL:
            case Result::NEUTRAL:
                return false;
            case Result::TEMPERROR:
                throw new TempErrorException();
            case Result::PERMERROR:
            case Result::NONE:
            default:
                throw new PermErrorException('Include resulted in a ' . $includeResult->getResult());
        }
    }
}
