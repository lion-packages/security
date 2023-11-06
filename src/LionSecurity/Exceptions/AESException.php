<?php

declare(strict_types=1);

namespace LionSecurity\Exceptions;

use Exception;

class AESException extends Exception
{
    public function __construct($message, $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
