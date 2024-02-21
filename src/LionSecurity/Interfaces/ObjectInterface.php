<?php

declare(strict_types=1);

namespace Lion\Security\Interfaces;

use Lion\Security\AES;
use Lion\Security\RSA;

interface ObjectInterface
{
    /**
     * Converts the list with data to an object
     * */
    public function toObject(): AES|RSA;
}
