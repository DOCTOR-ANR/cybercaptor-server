############################################################
# Dockerfile to build and run the FIWARE CyberCAPTOR Server
# Based on Ubuntu
############################################################

# Use phusion/baseimage as base image. For more information,
# see https://phusion.github.io/baseimage-docker/
FROM phusion/baseimage:0.9.16

# Configure local DNS and proxy (remove / change for build from another location)
ENV http_proxy http://10.222.146.131:80/
ENV https_proxy http://10.222.146.131:3128/
ENV HTTP_PROXY http://10.222.146.131:80/
ENV HTTPS_PROXY http://10.222.146.131:3128/
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


# Install git-lfs
RUN mkdir -p /data/build/
WORKDIR /data/build
RUN wget -O git-lfs_2.0.2_amd64.deb https://packagecloud.io/github/git-lfs/packages/debian/jessie/git-lfs_2.0.2_amd64.deb/download
RUN dpkg -i git-lfs_2.0.2_amd64.deb
RUN git lfs install

# Build XSB and move it to /opt/
RUN wget http://xsb.sourceforge.net/downloads/XSB360.tar.gz
RUN tar xzf XSB360.tar.gz
WORKDIR /data/build/XSB/build
RUN ./configure
RUN ./makexsb
RUN cp -R /data/build/XSB/ /opt/XSB

# Build MulVAL and move it to /opt/
WORKDIR /data/build/
# It's not the original MulVAL, use this repository instead !
RUN git clone https://github.com/fiware-cybercaptor/mulval.git
WORKDIR /data/build/mulval
ENV MULVALROOT=/data/build/mulval
RUN make
RUN cp -R /data/build/mulval /opt/mulval
ENV MULVALROOT=/opt/mulval

# Add the sources and build the Web Archive using Maven
WORKDIR /data/build/
ADD . /data/build/cybercaptor-server
WORKDIR /data/build/cybercaptor-server/
# If we are in a working copy, remove uncommitted changes
RUN git reset --hard HEAD
# Add proxy config for maven
RUN mkdir /root/.m2
RUN cp -r /data/build/cybercaptor-server/container/m2-settings.xml /root/.m2/settings.xml
RUN mvn package
RUN mv ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war

# Add the cyber-data-extract script and install its dependences
WORKDIR /root/
RUN mkdir /root/.remediation
RUN cp -r /data/build/cybercaptor-server/cyber-data-extract /root/.remediation/cyber-data-extract
WORKDIR /root/.remediation/cyber-data-extract
RUN pip install -r requirements.txt

# Add the necessary configuration files, the vulnerability database and test inputs files
RUN cp -R /data/build/cybercaptor-server/configuration-files /root/.remediation/
RUN cp /data/build/cybercaptor-server/configuration-files/config.properties.root /root/.remediation/config.properties
RUN mkdir /opt/cybercaptor
RUN cp /data/build/cybercaptor-server/vulnerability-remediation-database.db /opt/cybercaptor/vulnerability-remediation-database.db
ENV VULNERABILITY_DATABASE_PATH /opt/cybercaptor/vulnerability-remediation-database.db

# Clean up
RUN rm -rf ~/.m2

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
