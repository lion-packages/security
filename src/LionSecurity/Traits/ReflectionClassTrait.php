<?php

declare(strict_types=1);

namespace LionSecurity\Traits;

use ReflectionClass;

trait ReflectionClassTrait
{
    private $instance;
    private ReflectionClass $reflectionClass;

    protected function init($instance): void
    {
        $this->instance = $instance;
        $this->reflectionClass = new ReflectionClass($this->instance);
    }

    /**
     * Gets the value of a private property of a class
     * */
    protected function getPrivateProperty($property): mixed
    {
        $property = $this->reflectionClass->getProperty($property);
        $property->setAccessible(true);

        return $property->getValue($this->instance);
    }
}
