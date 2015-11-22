#!/bin/bash

HOST=orin.kylewm.com
REMOTE_PATH=/srv/www/silo.pub/silopub

ssh $HOST bash -c "'

set -x
cd $REMOTE_PATH

git pull origin master \
&& source venv/bin/activate \
&& pip install --upgrade -r requirements.txt \
&& sudo restart silopub

'"
