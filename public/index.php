<?php

declare(strict_types=1);

header('Content-Type: application/json');

require_once(__DIR__ . '/../vendor/autoload.php');

use Lion\Security\JWT;

echo(json_encode((new JWT)->getJWT()));
