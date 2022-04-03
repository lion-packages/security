# Lion-Security
## Library created with the function of implementing AES, RSA and JWT Security functions for PHP.
[![Latest Stable Version](http://poser.pugx.org/lion-framework/lion-security/v)](https://packagist.org/packages/lion-framework/lion-security) [![Total Downloads](http://poser.pugx.org/lion-framework/lion-security/downloads)](https://packagist.org/packages/lion-framework/lion-security) [![Latest Unstable Version](http://poser.pugx.org/lion-framework/lion-security/v/unstable)](https://packagist.org/packages/lion-framework/lion-security) [![License](http://poser.pugx.org/lion-framework/lion-security/license)](https://packagist.org/packages/lion-framework/lion-security) [![PHP Version Require](http://poser.pugx.org/lion-framework/lion-security/require/php)](https://packagist.org/packages/lion-framework/lion-security)

## Install
```
composer require lion-framework/lion-security
```

## Usage
### 1. RSA
RSA interacts with properties set in `.env`, where the properties we use must be specified. <br>

- RSA_PATH
- RSA_PRIVATE_KEY_BITS
- RSA_DEFAULT_MD

#### Example

- RSA_PATH="C:/xampp/php/extras/openssl/openssl.cnf"
- RSA_PRIVATE_KEY_BITS=2048
- RSA_DEFAULT_MD="sha256"

To create the public and private key, it can be done in 2 ways. Keep in mind that the classes required for its operation must be imported. More information on [FILES](https://github.com/Sleon4/Lion-Files). <br>
```php
use LionSecurity\RSA;
use LionFiles\FILES;
```

LionFiles is an external library, We call the folder function to create the folders of the established path, `FILES::folder('path')` takes care of creating the folders of a given path. <br>

#### Example #1.
In this first option we can create the keys automatically in an internally established route `'resources/upload_files/'`, which when looking at your directories will have new folders and files in the respective `'resources/upload_files/'` path.
```php
FILES::folder();
RSA::createKeys();

return [
	'status' => 'success',
	'message' => 'Keys created successfully.'
];
```

#### Example #2.
In this second option we can specify which folders we are going to create, which will be where the public and private keys will be stored.
```php
$path = 'resources/my_secret_folder/';
FILES::folder($path);
RSA::createKeys($path);

return [
	'status' => 'success',
	'message' => 'Keys created successfully.'
];
```

Note that the public and private key creation operation must be executed. <br>
An example of execution could be to make an HTTP request where they execute the creation of keys, more information on the use of [Route](https://github.com/Sleon4/Lion-Route).
```php
Route::post('create-key', function() {
	FILES::folder();
	RSA::createKeys();

	return [
		'status' => 'success',
		'message' => 'Keys created successfully.'
	];
});
```

### 1.1 RSA ENCODE
To encrypt data with aes an stdClass object must be specified, You must send an array and parse it.
```php
$data = (object) [
	'email' => "myemail2022@example.com",
	'password' => "mypass1234"
];
```

The created object must be sent to the encryption function to encrypt the data. <br>
```php
use LionSecurity\RSA;

$rsaEnc = RSA::encode($data);
var_dump($rsaEnc);
```

### 1.2 RSA DECODE
The created object must be sent to the encryption function to encrypt the data. <br>
```php
$rsaDec = RSA::decode($rsaEnc);
var_dump($rsaDec);
```

### 2. AES
AES interacts with the properties set in .env, where the properties we use must be specified.

- AES_METHOD
- AES_KEY
- AES_IV

#### Example

- AES_METHOD="aes-256-cbc"
- AES_KEY="AES_KEY-12345-KY"
- AES_IV="AES_IV-123456-IV"

### 2.1 AES ENCODE
To encrypt data with aes an stdClass object must be specified, You must send an array and parse it.
```php
$data = (object) [
	'email' => "myemail2022@example.com",
	'password' => "mypass1234"
];
```

The created object must be sent to the encode function to encrypt the data, additionally specify the `.env` properties which the function will use for data encryption. <br>
Note that the `AES_KEY` and `AES_IV` properties are extracted directly from the `.env` file.
```php
use LionSecurity\AES;

$aesEnc = AES::encode($data, 'AES_KEY', 'AES_IV');
var_dump($aesEnc);
```

### 2.2 AES DECODE
The created object must be sent to the encode function to encrypt the data, additionally specify the `.env` properties which the function will use for data encryption. <br>
Note that the `AES_KEY` and `AES_IV` properties are extracted directly from the `.env` file.
```php
$aesDec = AES::decode($aesEnc, 'AES_KEY', 'AES_IV');
var_dump($aesDec);
```

### 3. JWT
JWT interacts with the properties established in `.env`, where the properties we use must be specified. It is mandatory to create the public and private key with RSA beforehand, because JWT requires a public and private key for its operation.

- SERVER_URL
- SERVER_URL_AUD
- JWT_DEFAULT_MD
- JWT_EXP

#### Example

- SERVER_URL="http://localhost/Lion-Framework/Lion-Security/"
- SERVER_URL_AUD="http://localhost:3000/"
- JWT_DEFAULT_MD="RS256"
- JWT_EXP=86400

### 3.1 JWT ENCODE
The function works with 2 parameters, The first parameter is an array with the data to be added to the JWT, The second parameter is optional and it is the lifetime of the JWT.
```php
use LionSecurity\JWT;
$data = [
	'idUsers' => 1,
	'idRoles' => 3
];

$jwtEnc = JWT::encode($data);
var_dump($jwtEnc);
```

Note that the default time that the JWT has is 24 hours. You can change the time by sending an integer as the second parameter. <br>
With this, it is established that the JWT will have a duration of 300 seconds, which is equivalent to 5 minutes.
```php
use LionSecurity\JWT;
$data = [
	'idUsers' => 1,
	'idRoles' => 3
];

$jwtEnc = JWT::encode($data, 300);
var_dump($jwtEnc);
```

### 3.2 JWT DECODE
To decrypt the JWT, the generated JWT string must be sent.
```php
$jwtDec = JWT::decode($jwtEnc);
var_dump($jwtDec);
```

### 3.3 RETRIEVE JWT
In order to retrieve the JWT, It must be sent through a header. When sending your HTTP request, Ihe JWT is not attached to the data, So we must obtain the JWT from the headers sent.
```php
$jwtDec = JWT::decode(JWT::getToken());
var_dump($jwtDec);
```

### 4. SECURITY
The security class is implemented to dynamically work some methods.

 - SHA256
	This function receives as a parameter an object of type stdClass, which we must fill an array with all the data that we want to encrypt with sha256 and parse it into an object. <br>
	More information at [php.net](https://www.php.net/manual/es/function.hash).
	```php
	use LionSecurity\SECURITY;

	$password = (object) [
		'password' => "root1234",
		'email' => "example@example.com"
	];

	$password = SECURITY::sha256($password);
	var_dump($password);
	```

 - PASSWORD HASH
	This function works with 2 parameters, The first parameter is a string which is going to be encrypted, The second parameter is optional and it is an array with the configuration attributes. <br>
	More information at [php.net](https://www.php.net/manual/es/function.password-hash.php).
	```php
	$password = SECURITY::passwordHash("root1234");
	var_dump($password);
	```

 - PASSWORD VERIFY
	This function checks if the 2 passwords sent are the same. <br>
	More information at [php.net](https://www.php.net/manual/es/function.password-verify).
	```php
	$password = "...";
	$passwordConfirm = "...";

	$request = SECURITY::passwordVerify($password, $passwordConfirm);
	var_dump($request)
	```

 - VALIDATE
	This function interacts with [VALITRON](https://github.com/vlucas/valitron), The first parameter is an array with all the properties which we are going to verify if they meet the established requirements, The second parameter is an array the which contains all the rules which specify all the parameters to check. <br>
	More information at [VALITRON](https://github.com/vlucas/valitron#built-in-validation-rules).
	```php
	$request = SECURITY::validate([], []);
	var_dump($request)
	```

## Credits
[PHP dotenv](https://github.com/vlucas/phpdotenv) <br>
[Valitron](https://github.com/vlucas/valitron) <br>
[PHP-JWT](https://github.com/firebase/php-jwt)

## License
Copyright © 2022 [MIT License](https://github.com/Sleon4/Lion-Security/blob/main/LICENSE)