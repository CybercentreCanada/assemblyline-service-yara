ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Python path to the service class from your service directory
ENV SERVICE_PATH=yara_.yara_.Yara

# Install apt dependencies
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

USER root
# Copy Yara service code
WORKDIR /opt/al_service
COPY ./yara_ ./yara_

# Setting service manifest
RUN mv yara_/service_manifest.yml .

# Cleanup
RUN rm yara_/Dockerfile

# Set owner
RUN chown -R assemblyline /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
