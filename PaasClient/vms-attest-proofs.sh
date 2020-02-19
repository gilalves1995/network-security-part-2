#!/bin/bash

ls -l /bin/bash

# echo osboxes.org | sudo -S docker ps -a | grep redis-server
# echo osboxes.org | sudo -S docker images
docker ps -a | grep redis-server
docker images

ls -l /usr/local/bin/redis-server
ls -l /usr/bin/docker
ls -l /usr/bin/java

