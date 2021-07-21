#!/bin/sh
docker ps | tail -n +2 | rev | awk '{print $1}' | rev | xargs docker kill
