<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\MechanismEvaluator;

use Nzldev\SPFCheck\Exception\DNSLookupException;
use Nzldev\SPFCheck\Exception\TempErrorException;
use Nzldev\SPFCheck\MacroUtils;
use Nzldev\SPFCheck\Mechanism\AbstractMechanism;
use Nzldev\SPFCheck\Mechanism\Exists;
use Nzldev\SPFCheck\Model\Query;
use Nzldev\SPFCheck\Model\Result;

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
