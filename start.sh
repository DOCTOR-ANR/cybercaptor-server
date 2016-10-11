#!/bin/bash
cd /data/build/cybercaptor-server/cybercaptor-client
python -m SimpleHTTPServer 8000 &
/sbin/my_init
