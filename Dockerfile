############################################################
# Dockerfile to build and run the FIWARE CyberCAPTOR Server
# Based on Ubuntu
############################################################

# Use phusion/baseimage as base image. For more information,
# see https://phusion.github.io/baseimage-docker/
FROM phusion/baseimage:0.9.16

# Configure local DNS and proxy
RUN export http_proxy="http://10.222.146.131:80/"
RUN export https_proxy="http://10.222.146.131:3128/"
RUN export HTTP_PROXY="http://10.222.146.131:80/"
RUN export HTTPS_PROXY="http://10.222.146.131:3128/"
RUN echo "nameserver 10.222.148.2" > /etc/resolv.conf

RUN echo "Acquire::http::proxy \"http://apt.theresis.org:3142\";" >> /etc/apt/apt.conf

# Use baseimage-docker's init system.
CMD ["/data/build/cybercaptor-server/start.sh"]

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

# Build XSB and move it to /opt/
RUN mkdir -p /data/build/
WORKDIR /data/build/
RUN wget -e http_proxy=http://10.222.146.131:80/ http://xsb.sourceforge.net/downloads/XSB360.tar.gz
RUN tar xzf XSB360.tar.gz
WORKDIR /data/build/XSB/build
RUN ./configure
RUN ./makexsb
RUN cp -R /data/build/XSB/ /opt/XSB

# Build MulVAL and move it to /opt/
WORKDIR /data/build/
RUN HTTPS_PROXY=http://10.222.146.131:3128/ git clone https://github.com/fiware-cybercaptor/mulval.git
WORKDIR /data/build/mulval
ENV MULVALROOT=/data/build/mulval
RUN make
RUN cp -R /data/build/mulval /opt/mulval
ENV MULVALROOT=/opt/mulval

# Add the sources and build the Web Archive using Maven
#WORKDIR /data/build/
#RUN git clone -q https://github.com/fiware-cybercaptor/cybercaptor-server.git
# Directly copy the files from the local machine
WORKDIR /data/build/
ADD . /data/build/cybercaptor-server
WORKDIR /data/build/cybercaptor-server/
# We are in a working copy !
RUN git reset --hard HEAD
# Add proxy config for maven
RUN mkdir /root/.m2
RUN cp -r /data/build/cybercaptor-server/container/m2-settings.xml /root/.m2/settings.xml
RUN mvn package
RUN mv ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war

# Add the python script and its dependencies
WORKDIR /root/
#RUN git clone -q https://github.com/fiware-cybercaptor/cyber-data-extraction.git
# Directly copy the files from the local machine
RUN mkdir /root/.remediation
RUN cp -r /data/build/cybercaptor-server/cyber-data-extract /root/.remediation/cyber-data-extract
WORKDIR /root/.remediation/cyber-data-extract
RUN HTTPS_PROXY=http://10.222.146.131:3128/ pip install -r requirements.txt

# Add the necessary configuration files, the vulnerability database and test inputs files
RUN cp -R /data/build/cybercaptor-server/configuration-files /root/.remediation/
RUN cp /data/build/cybercaptor-server/configuration-files/config.properties.root /root/.remediation/config.properties
#RUN wget -O /root/.remediation/vulnerability-remediation-database.db https://github.com/fiware-cybercaptor/cyber-data-extraction/releases/download/4.4.1/vulnerability-remediation-database.db
# Directly copy the files from the local machine
RUN mkdir /opt/cybercaptor
RUN cp /data/build/cybercaptor-server/vulnerability-remediation-database.db /opt/cybercaptor/vulnerability-remediation-database.db
ENV VULNERABILITY_DATABASE_PATH /opt/cybercaptor/vulnerability-remediation-database.db

# Clean up
RUN rm -rf ~/.m2
#RUN rm -rf /data/

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
