<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\MacroUtils;
use Nzldev\ToolsSPFCheck\Mechanism\A;
use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;
use Symfony\Component\HttpFoundation\IpUtils;

class AEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if (!$mechanism instanceof A) {
            throw new \LogicException();
        }
        $targetVersion = str_contains($query->getIpAddress(), ':') ? 6 : 4;

        $hostname = $mechanism->getHostname();
        $hostname = MacroUtils::expandMacro($hostname, $query, $result->getDNSSession(), false);
        $hostname = MacroUtils::truncateDomainName($hostname);
        $aRecords = $result->getDNSSession()->resolveA($hostname);
        if (empty($aRecords)) {
            $result->countVoidLookup();
        }

        $cidr = $targetVersion === 6 ? $mechanism->getCidr6() : $mechanism->getCidr4();
        foreach ($aRecords as $record) {
            $recordVersion = str_contains($record, ':') ? 6 : 4;
            if ($recordVersion !== $targetVersion) {
                continue;
            }
            if (IpUtils::checkIp($query->getIpAddress(), $record . '/' . $cidr)) {
                return true;
            }
        }

        return false;
    }
}
