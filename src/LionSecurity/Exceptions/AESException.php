<?php

declare(strict_types=1);

namespace Lion\Security\Exceptions;

use Exception;

/**
 * This class represents custom exceptions for AES class processes
 *
 * @package Lion\Security\Exceptions
 */
class AESException extends Exception
{
    /**
     * Constructor method of the class
     *
     * @param string $message [The Exception message to throw]
     * @param int $code [The Exception code]
     * @param Exception|null $previous [The previus Throwable used for the
     * exception chaining]
     */
    public function __construct(string $message, int $code = 0, ?Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
