# PHP-SPF-Check

Simple library to check an IP address against a domain's [SPF](http://www.openspf.org/) record

## Installation
This library is available through Composer.
Run `composer require techzolab/toolsspfcheck` or add this to your composer.json:
```json
{
  "require": {
    "techzolab/toolsspfcheck": "^1"
  }
}
```

## Usage
Create a new instance of ToolsSPFCheck. The constructor requires a DNSRecordGetterInterface to be passed. Currently, you have two options:
- `DNSRecordGetter` which uses PHP's DNS functions to get data
- `DNSRecordGetterDirect` which uses the [PHP DNS Direct Query Module](https://github.com/purplepixie/phpdns) to get data.
```php
<?php
use Nzldev\ToolsSPFCheck\ToolsSPFCheck;
use Nzldev\ToolsSPFCheck\DNSRecordGetter;

require('vendor/autoload.php');

$checker = new ToolsSPFCheck(new DNSRecordGetter()); // Uses php's dns_get_record method for lookup.
var_dump($checker->isIPAllowed('127.0.0.1', 'test.com'));

// or

$checker = new ToolsSPFCheck(new DNSRecordGetterDirect("8.8.8.8")); // Uses phpdns, allowing you to set the nameserver you wish to use for the dns queries.
var_dump($checker->isIPAllowed('127.0.0.1', 'test.com'));
```

Return value is one of `ToolsSPFCheck::RESULT_PASS`, `ToolsSPFCheck::RESULT_FAIL`, `ToolsSPFCheck::RESULT_SOFTFAIL`, `ToolsSPFCheck::RESULT_NEUTRAL`, `ToolsSPFCheck::RESULT_NONE`, `ToolsSPFCheck::RESULT_PERMERROR`, `ToolsSPFCheck::RESULT_TEMPERROR`

## Missing features
A few features are still missing from this library at the moment. Here's a partial list of those features:
* [Section 7 of RFC7208](https://tools.ietf.org/html/rfc7208#section-7) on macros

You are very welcome to submit a pull request adding even part of those features.
