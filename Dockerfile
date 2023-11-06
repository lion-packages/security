FROM php:8.2-apache

RUN useradd -m lion && echo 'lion:lion' | chpasswd && usermod -aG sudo lion && usermod -s /bin/bash lion

RUN apt-get update -y \
    && apt-get install -y nano git curl wget unzip sendmail libpng-dev libzip-dev \
    && apt-get install -y zlib1g-dev libonig-dev supervisor libevent-dev libssl-dev \
    && pecl install ev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mbstring gd pdo_mysql mysqli zip \
    && docker-php-ext-enable gd zip

RUN a2enmod rewrite \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

COPY . .

CMD php -S 0.0.0.0:8000
