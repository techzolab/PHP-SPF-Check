<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\Mechanism;

use Nzldev\SPFCheck\Enum\Qualifier;
use Nzldev\SPFCheck\Model\Term;

abstract class AbstractMechanism extends Term
{
    private string $qualifier;

    /**
     * @param string $qualifier
     * @psalm-param Qualifier::* $qualifier
     */
    public function __construct(string $rawTerm, string $qualifier)
    {
        parent::__construct($rawTerm);
        $this->qualifier = $qualifier;
    }

    /**
     * @return string
     */
    public function getQualifier(): string
    {
        return $this->qualifier;
    }
}
