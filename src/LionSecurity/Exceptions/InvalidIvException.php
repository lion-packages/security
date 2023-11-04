<?php

declare(strict_types=1);

namespace LionSecurity\Exceptions;

use Exception;
use LionSecurity\Exceptions\AESException;

class InvalidIvException extends AESException
{
    public function __construct($message = "Invalid IV", $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
