<?php

declare(strict_types=1);

namespace SimpleSAML\Module\core\Auth\Process;

use SimpleSAML\Configuration;
use SimpleSAML\Auth\ConditionalProcessingFilterInserter;

/**
 * Conditionally create new authproc filters at the location of this filter
 */
class PhpConditionalAuthProcFilter extends ConditionalProcessingFilterInserter
{
    private string $condition;


    public function __construct(&$config, $reserved)
    {
        parent::__construct($config, $reserved);

        $conf = Configuration::loadFromArray($config);
        $this->condition = $conf->getString('condition');
    }


    protected function checkCondition(array &$state): bool
    {
        $function = /** @return bool */ function (
            array &$attributes,
            array &$state
        ) {
            return eval($this->condition);
        };

        return $function($state['Attributes'], $state) === true;
    }
}
