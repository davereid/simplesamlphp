<?php

declare(strict_types=1);

namespace SimpleSAML\Auth;

use ReflectionClass;
use SimpleSAML\Logger;

use function array_splice;
use function count;
use function sprintf;

/**
 * Aids in letting an authproc filter create and insert additional authproc filters
 */
class ProcessingChainRuleInserter
{
    /**
     * @param array $state
     * @psalm-param array{"\\\SimpleSAML\\\Auth\\\ProcessingChain.filters": array} $state
     * @param ProcessingFilter[] $authProcs
     */
    public function insertFilters(array &$state, array $authProcs): void
    {
        if (count($authProcs) === 0) {
            return;
        }

        Logger::debug(sprintf(
            'ProcessingChainRuleInserter: Adding %d additional filters before remaining %d',
            count($authProcs),
            count($state[ProcessingChain::FILTERS_INDEX]),
        ));

        array_splice($state[ProcessingChain::FILTERS_INDEX], 0, 0, $authProcs);
    }


    /**
     * @param array $state
     * @psalm-param array{"\\\SimpleSAML\\\Auth\\\ProcessingChain.filters": array} $state
     * @param array $authProcConfigs
     * @return ProcessingFilter[]
     */
    public function createAndInsertFilters(array &$state, array $authProcConfigs): array
    {
        $processingChain = new ReflectionClass(ProcessingChain::class);
        $parseMethod = $processingChain->getMethod('parseFilterList');
        $parseMethod->setAccessible(true);

        /** @var \SimpleSAML\Auth\ProcessingFilter[] $filters */
        $filters = $parseMethod->invoke(null, $authProcConfigs);
        $this->insertFilters($state, $filters);

        return $filters;
    }
}
