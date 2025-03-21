FROM php:8.4-apache

ARG DEBIAN_FRONTEND=noninteractive
# ----------------------------------------------------------------------------------------------------------------------
USER root

# Add User
RUN useradd -m lion && echo 'lion:lion' | chpasswd && usermod -aG sudo lion && usermod -s /bin/bash lion

# Dependencies
RUN apt-get update -y \
    && apt-get install -y sudo nano zsh git curl wget unzip cron sendmail golang-go libpng-dev libzip-dev zlib1g-dev \
    && apt-get install -y libonig-dev libevent-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure PHP-Extensions
RUN pecl install xdebug \
    && docker-php-ext-install mbstring gd zip \
    && docker-php-ext-enable gd zip xdebug \
    && a2enmod rewrite

# Configure Xdebug
RUN echo "xdebug.mode=develop,coverage,debug" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.remote_autostart=off" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.remote_connect_back=off" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.start_with_request=yes" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.idekey=docker" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.log=/dev/stdout" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.log_level=0" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.client_host=host.docker.internal" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini \
    && echo "xdebug.client_port=9000" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
# ----------------------------------------------------------------------------------------------------------------------
USER lion

SHELL ["/bin/bash", "--login", "-i", "-c"]

# Install OhMyZsh
RUN sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"
# ----------------------------------------------------------------------------------------------------------------------
USER root

SHELL ["/bin/bash", "--login", "-c"]

# Install logo-ls
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        wget https://github.com/Yash-Handa/logo-ls/releases/download/v1.3.7/logo-ls_amd64.deb; \
    elif [ "$ARCH" = "aarch64" ]; then \
        wget https://github.com/Yash-Handa/logo-ls/releases/download/v1.3.7/logo-ls_arm64.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    dpkg -i logo-ls_*.deb && \
    rm logo-ls_*.deb && \
    curl https://raw.githubusercontent.com/UTFeight/logo-ls-modernized/master/INSTALL | bash

# Add configuration in .zshrc
RUN echo 'alias ls="logo-ls"' >> /home/lion/.zshrc \
    && source /home/lion/.zshrc
# ----------------------------------------------------------------------------------------------------------------------
# Copy Data
COPY . .
# ----------------------------------------------------------------------------------------------------------------------
# Init Project
CMD php -S 0.0.0.0:8000 -t public
