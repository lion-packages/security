<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

/**
 * Represents the implementation for converting data from lists to objects
 *
 * @package Lion\Security\Interfaces
 */
interface ObjectInterface
{
    /**
     * Converts the list with data to an object
     *
     * @return ObjectInterface
     * */
    public function toObject(): ObjectInterface;
}
