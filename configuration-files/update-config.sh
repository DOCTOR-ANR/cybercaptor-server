#!/bin/bash
cp config.properties config.properties.root
sed -i -e 's/\/home\/T0160040\/cybercaptor-server/\/root\/.remediation/g' config.properties.root
