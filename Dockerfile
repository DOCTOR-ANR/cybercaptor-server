############################################################
# Dockerfile to build and run the FIWARE CyberCAPTOR Server
# Based on Ubuntu
############################################################

# Use phusion/baseimage as base image. For more information,
# see https://phusion.github.io/baseimage-docker/
FROM phusion/baseimage:0.9.16

# Configure local DNS and proxy (remove / change for build from another location)
ARG MY_HTTP_PROXY="http://10.222.146.131:80/"
ARG MY_HTTPS_PROXY="http://10.222.146.131:3128/"
ARG MY_NAME_SERVER="10.222.148.2"

RUN export http_proxy="${MY_HTTP_PROXY}"
RUN export https_proxy="${MY_HTTPS_PROXY}"
RUN export HTTP_PROXY="${MY_HTTP_PROXY}"
RUN export HTTPS_PROXY="${MY_HTTPS_PROXY}"
RUN echo "nameserver ${MY_NAME_SERVER}" > /etc/resolv.conf
RUN echo "Acquire::http::proxy \"http://apt.theresis.org:3142\";" >> /etc/apt/apt.conf

# Use baseimage-docker's init system.
#CMD ["/data/build/cybercaptor-server/start.sh"]
CMD ["/root/cybercaptor-start.sh"]

# Install dependencies to build XSB, build MulVAL, build the .war, install python dependencies
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
  bison \
  flex \
  g++ \
  git \
  gcc \
  make \
  maven \
  openjdk-7-jdk \
  python-pip \
  sqlite3 \
  tomcat7 \
  wget \
  && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# create working directory
RUN mkdir -p /data/build/
WORKDIR /data/build

# Install git-lfs
RUN wget -e https_proxy="${MY_HTTPS_PROXY}" -O git-lfs_2.0.2_amd64.deb https://packagecloud.io/github/git-lfs/packages/debian/jessie/git-lfs_2.0.2_amd64.deb/download
RUN dpkg -i git-lfs_2.0.2_amd64.deb
RUN git lfs install

# Build XSB and move it to /opt/
RUN wget -e http_proxy="${MY_HTTP_PROXY}" http://xsb.sourceforge.net/downloads/XSB360.tar.gz
RUN tar xzf XSB360.tar.gz
WORKDIR /data/build/XSB/build
RUN ./configure
RUN ./makexsb
#ici RUN cp -R /data/build/XSB/ /opt/XSB
RUN mv /data/build/XSB /opt/

# Build MulVAL and move it to /opt/
WORKDIR /data/build/
# It's not the original MulVAL, use this repository instead !
RUN HTTPS_PROXY="${MY_HTTPS_PROXY}" git clone https://github.com/fiware-cybercaptor/mulval.git
WORKDIR /data/build/mulval
ENV MULVALROOT=/data/build/mulval
RUN make
#RUN cp -R /data/build/mulval /opt/mulval
RUN mv /data/build/mulval /opt/
ENV MULVALROOT=/opt/mulval

# Add the sources 
WORKDIR /data/build/
ADD .   /data/build/cybercaptor-server
WORKDIR /data/build/cybercaptor-server/

# mv cybercaptor server start shell script
RUN mv /data/build/cybercaptor-server/start.sh /root/cybercaptor-start.sh

# Add proxy config for maven
# NB: this is performed before the git reset, in order to enable usage of a changed non-commited m2-setting.xml file
RUN mkdir /root/.m2
RUN cp -r /data/build/cybercaptor-server/container/m2-settings.xml /root/.m2/settings.xml

# If we are in a working copy, remove uncommitted changes
#RUN HTTPS_PROXY="${MY_HTTPS_PROXY}" git reset --hard HEAD

# build the Web Archive using Maven
RUN mvn package
RUN mv ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war

# Add the cyber-data-extract script and install its dependences
WORKDIR /root/
RUN mkdir /root/.remediation
RUN cp -r /data/build/cybercaptor-server/cyber-data-extract /root/.remediation/cyber-data-extract
WORKDIR /root/.remediation/cyber-data-extract
RUN HTTPS_PROXY="${MY_HTTPS_PROXY}" pip install -r requirements.txt

# Add the necessary configuration files, the vulnerability database and test inputs files
RUN cp -R /data/build/cybercaptor-server/configuration-files /root/.remediation/
RUN cp /data/build/cybercaptor-server/configuration-files/config.properties.root /root/.remediation/config.properties
RUN mkdir /opt/cybercaptor
#RUN cp /data/build/cybercaptor-server/vulnerability-remediation-database.db /opt/cybercaptor/vulnerability-remediation-database.db
RUN mv /data/build/cybercaptor-server/vulnerability-remediation-database.db /opt/cybercaptor/
ENV VULNERABILITY_DATABASE_PATH /opt/cybercaptor/vulnerability-remediation-database.db

# Clean up
RUN rm -rf ~/.m2 
# TODO don't remove /data/build/cybercaptor-server/cybercaptor-client and cyber-data-extract !!!
#RUN rm -rf /data

# Prepare tomcat7
ENV CATALINA_BASE=/var/lib/tomcat7
ENV CATALINA_HOME=/usr/share/tomcat7
RUN mkdir /var/lib/tomcat7/temp

RUN mkdir /etc/service/tomcat7
ADD container/tomcat7.sh /etc/service/tomcat7/run
RUN chmod a+x /etc/service/tomcat7/run

EXPOSE 8080
EXPOSE 8000

WORKDIR /root/.remediation

