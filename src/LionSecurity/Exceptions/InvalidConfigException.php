<?php

declare(strict_types=1);

namespace LionSecurity\Exceptions;

use Exception;

class InvalidConfigException extends AESException
{
    public function __construct($message = "Invalid Config", $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
