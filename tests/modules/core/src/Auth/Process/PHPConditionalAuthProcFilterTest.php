<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Auth\Process;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\core\Auth\Process\AttributeAdd;
use SimpleSAML\Module\core\Auth\Process\AttributeLimit;
use SimpleSAML\Module\core\Auth\Process\PHPConditionalAuthProcFilter;

class PhpConditionalAuthProcFilterTest extends TestCase
{
    /**
     * @dataProvider falseConditionProvider
     * @param array|null $elseAuthProcConfig if any elseAuthproc confiugrations should be sent to filter
     * @param array $expectedClasses The class names expected in the authproc state
     * @return void
     * @throws \SimpleSAML\Error\Exception
     */
    public function testFalseCondition(?array $elseAuthProcConfig, array $expectedClasses): void
    {
        $config = [
            //php code
            'condition' => 'return false;',
            //authprocs
            'authproc' => [
                [
                    'class' => 'core:AttributeAdd',
                    'source' => ['myidp'],
                ],
            ]
        ];
        if (!is_null($elseAuthProcConfig)) {
            $config['elseAuthproc'] = $elseAuthProcConfig;
        }
        $limitConfig = [];
        $state = [
            'Attributes' => [],
            ProcessingChain::FILTERS_INDEX => [
                new AttributeLimit($limitConfig, [])
            ]
        ];
        $filter = new PHPConditionalAuthProcFilter($config, []);
        $filter->process($state);
        $this->assertCount(count($expectedClasses), $state[ProcessingChain::FILTERS_INDEX]);
        $counter = 0;
        foreach ($expectedClasses as $expectedClass) {
            $this->assertInstanceOf($expectedClass, $state[ProcessingChain::FILTERS_INDEX][$counter++]);
        }
    }

    public static function falseConditionProvider(): array
    {
        return [
            [null, [AttributeLimit::class]],
            [[], [AttributeLimit::class]],
        ];
    }

    /**
     * @dataProvider trueConditionProvider
     * @param array|null $authProcConfig
     * @param array $expectedClasses
     * @return void
     * @throws \SimpleSAML\Error\Exception
     */
    public function testTrueCondition(?array $authProcConfig, array $expectedClasses): void
    {
        $config = [
            'condition' => 'return $state["saml:sp:State"]["saml:sp:AuthnContext"] === "https://refeds.org/profile/mfa";',
            'elseAuthproc' => [
                [
                    'class' => 'core:AttributeMap',
                ],
            ]
        ];
        if (!is_null($authProcConfig)) {
            $config['authproc'] = $authProcConfig;
        }
        $limitConfig = [];
        $state = [
            "saml:sp:State" => ['saml:sp:AuthnContext' => 'https://refeds.org/profile/mfa'],
            'Attributes' => [],
            ProcessingChain::FILTERS_INDEX => [
                new AttributeLimit($limitConfig, [])
            ]
        ];
        $filter = new PHPConditionalAuthProcFilter($config, []);
        $filter->process($state);
        $this->assertCount(count($expectedClasses), $state[ProcessingChain::FILTERS_INDEX]);
        $counter = 0;
        foreach ($expectedClasses as $expectedClass) {
            $this->assertInstanceOf($expectedClass, $state[ProcessingChain::FILTERS_INDEX][$counter++]);
        }
    }

    public static function trueConditionProvider(): array
    {
        return [
            [null, [AttributeLimit::class]],
            [[], [AttributeLimit::class]],
            [[
                [
                    'class' => 'core:AttributeAdd',
                ]
            ], [AttributeAdd::class, AttributeLimit::class]],
        ];
    }
}
