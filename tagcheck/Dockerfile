FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH tagcheck.tagcheck.TagCheck

######################################
# Tagcheck will now use yara for it's syntax, let's install yara the same way then the yara service
RUN apt-get update && apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v3.11.0.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-3.11.0
RUN ./bootstrap.sh
RUN ./configure --enable-magic --enable-dotnet --with-crypto
RUN make
RUN make install

RUN pip install yara-python gitpython plyara
# Done installing yara
#####################################

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service/yara_
RUN mkdir -p /opt/al_service/tagcheck

# Copy Tagcheck service code
WORKDIR /opt/al_service
COPY ./yara_ ./yara_
COPY ./tagcheck ./tagcheck

# Setting service manifest
RUN mv tagcheck/service_manifest.yml .

# Cleanup
RUN rm tagcheck/Dockerfile
RUN rm yara_/service_manifest.yml
RUN rm yara_/Dockerfile

# Set owner
RUN chown -R assemblyline /opt/al_service

# Switch to assemblyline user
USER assemblyline