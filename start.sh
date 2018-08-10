#!/bin/bash
cd /data/build/cybercaptor-server/cybercaptor-client
python -m SimpleHTTPServer 8000 &

cat /data/build/cybercaptor-server/logging.properties > /etc/tomcat7/logging.properties

/sbin/my_init
