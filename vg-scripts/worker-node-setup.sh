#!/bin/bash

# Ensure packages are up to date
apt-get update
apt-get upgrade -y

# Получение команды для присоединения к кластеру
JOIN_COMMAND=$(ssh -o StrictHostKeyChecking=no root@server "kubeadm token create --print-join-command")

# Присоединение к кластеру
$JOIN_COMMAND
