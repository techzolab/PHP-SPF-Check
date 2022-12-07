<?php

declare(strict_types=1);

namespace Nzldev\ToolsSPFCheck\MechanismEvaluator;

use Nzldev\ToolsSPFCheck\MacroUtils;
use Nzldev\ToolsSPFCheck\Mechanism\AbstractMechanism;
use Nzldev\ToolsSPFCheck\Mechanism\MX;
use Nzldev\ToolsSPFCheck\Model\Query;
use Nzldev\ToolsSPFCheck\Model\Result;
use Symfony\Component\HttpFoundation\IpUtils;

class MXEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if (!$mechanism instanceof MX) {
            throw new \LogicException();
        }
        $targetVersion = str_contains($query->getIpAddress(), ':') ? 6 : 4;
        $cidr = $targetVersion === 6 ? $mechanism->getCidr6() : $mechanism->getCidr4();

        $hostname = $mechanism->getHostname();
        $hostname = MacroUtils::expandMacro($hostname, $query, $result->getDNSSession(), false);
        $hostname = MacroUtils::truncateDomainName($hostname);

        $mxRecords = $result->getDNSSession()->resolveMX($hostname);
        foreach ($mxRecords as $ipAddresses) {
            $ipAddresses = array_filter($ipAddresses, function (string $address) use ($targetVersion): bool {
                $addressVersion = str_contains($address, ':') ? 6 : 4;
                return $addressVersion === $targetVersion;
            });
            $ipAddresses = array_map(function (string $address) use ($cidr): string {
                return $address . '/' . $cidr;
            }, $ipAddresses);

            if (IpUtils::checkIp($query->getIpAddress(), $ipAddresses)) {
                return true;
            }
        }

        return false;
    }
}
