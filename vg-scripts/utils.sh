#!/bin/bash

# Функция для логирования
log() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg"
}

# Функция для проверки ошибок
check_error() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local error_msg="${5:-}"

    if [[ $exit_code -ne 0 ]]; then
        log "Error occurred in script at line: $line_no"
        log "Command: $last_command"
        log "Exit code: $exit_code"
        log "Error message: $error_msg"
        exit $exit_code
    fi
}

# Функция для очистки временных файлов
cleanup() {
    log "Performing cleanup..."
    apt-get clean
    rm -rf /var/lib/apt/lists/*
}
