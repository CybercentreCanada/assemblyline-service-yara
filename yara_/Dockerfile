ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch
ENV SERVICE_PATH yara_.yara_.Yara

# Don't use the version of yara-python from assemblyline-base
USER assemblyline
RUN pip uninstall -y yara-python

# Install Python packages
# Pending: https://github.com/plyara/plyara/pull/130
RUN pip install --no-cache-dir --user git+https://github.com/cccs-rs/plyara.git
RUN pip install --no-cache-dir --user yara-x
RUN rm -rf ~/.cache/pip

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service/yara_

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
