ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base
ENV SERVICE_PATH yara_.yara_.Yara
ENV YARA_VERSION='4.3.0'

# Don't use the version of yara-python from assemblyline-base
USER assemblyline
RUN pip uninstall -y yara-python

# Install runtime libraries we will need later
USER root
RUN apt-get update && apt-get install -y libssl3 libmagic1 && rm -rf /var/lib/apt/lists/*

# Create a temporary image to do our compiling in
FROM base AS build

RUN apt-get update && apt-get install -y libssl-dev libmagic-dev automake libtool pkg-config make gcc wget  && rm -rf /var/lib/apt/lists/*

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-${YARA_VERSION}
RUN ./bootstrap.sh
RUN ./configure --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
RUN make
RUN make install

# Build the yara python plugins
USER assemblyline
RUN touch /tmp/before-pip
# Pending: https://github.com/plyara/plyara/pull/130
RUN pip install --no-cache-dir --user git+https://github.com/cccs-rs/plyara.git
RUN pip install --no-cache-dir --user --global-option="build" --global-option="--enable-magic" yara-python==${YARA_VERSION}
RUN rm -rf ~/.cache/pip

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Revert back to before the compile
FROM base

COPY --from=build /tmp/yara_install /usr/local
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local
RUN echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig

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
