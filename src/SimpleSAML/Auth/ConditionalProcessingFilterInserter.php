<?php

declare(strict_types=1);

namespace SimpleSAML\Auth;

use SimpleSAML\{Configuration, Logger};

/**
 * Conditionally create new authproc filters at the location of this filter
 */
abstract class ConditionalProcessingFilterInserter extends ProcessingFilter
{
    protected array $authProcs;

    protected array $elseAuthProcs;


    public function __construct(&$config, $reserved)
    {
        parent::__construct($config, $reserved);

        $conf = Configuration::loadFromArray($config);
        $this->authProcs = $conf->getOptionalArray('authproc', []);
        $this->elseAuthProcs = $conf->getOptionalArray('elseAuthproc', []);
    }


    public function process(array &$state): void
    {
        if ($this->checkCondition($state)) {
            $filtersToAdd = $this->authProcs;
            Logger::debug(sprintf(
                'ConditionalProcessingFilterInserter: true. Adding `authproc` filters: %d',
                count($filtersToAdd),
            ));
        } else {
            $filtersToAdd = $this->elseAuthProcs;
            Logger::debug(sprintf(
                'ConditionalProcessingFilterInserter: false. Adding `elseAuthproc` filters: %d',
                count($filtersToAdd),
            ));
        }

        $ruleInserter = new ProcessingChainRuleInserter();
        $ruleInserter->createAndInsertFilters($state, $filtersToAdd);
    }


   /**
     * @return bool true indicate `authproc` filters should be added. false to add `elseAuthproc`
     */
    abstract protected function checkCondition(array &$state): bool;
}
