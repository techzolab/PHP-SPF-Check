<?php

declare(strict_types=1);

namespace Nzldev\SPFCheck\Model;

abstract class Term
{
    protected string $rawTerm;

    public function __construct(string $rawTerm)
    {
        $this->rawTerm = $rawTerm;
    }
}
