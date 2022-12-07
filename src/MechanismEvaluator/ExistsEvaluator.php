<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\Exception\DNSLookupException;
use Nzldev\ToolsSPFCheck\Exception\TempErrorException;
use Nzldev\ToolsSPFCheck\MacroUtils;
use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Mechanism\Exists;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;

class ExistsEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if (!$mechanism instanceof Exists) {
            throw new \LogicException();
        }

        $hostname = $mechanism->getHostname();
        $hostname = MacroUtils::expandMacro($hostname, $query, $result->getDNSSession(), false);
        $hostname = MacroUtils::truncateDomainName($hostname);
        // 5.7/3: "The lookup type is A even when the connection type is IPv6"
        try {
            $records = $result->getDNSSession()->resolveA($hostname, true);
        } catch (DNSLookupException $e) {
            throw new TempErrorException('', 0, $e);
        }

        return !empty($records);
    }
}
