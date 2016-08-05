default: cybercaptor

cybercaptor:
	mvn package

.PHONY:
clean:
	mvn clean
install:
	cp ./target/cybercaptor-server*.war /var/lib/tomcat7/webapps/cybercaptor-server.war

