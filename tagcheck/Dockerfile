ARG build_type=latest
FROM cccs/assemblyline-service-yara:${build_type}

# Build the tagcheck container as a variant of the yara container where the additional
# tagcheck service code has been copied in
RUN mkdir -p /opt/al_service/tagcheck
COPY ./tagcheck ./tagcheck
RUN rm tagcheck/Dockerfile

# Over write the service path/manafest
ENV SERVICE_PATH tagcheck.tagcheck.TagCheck
RUN mv tagcheck/service_manifest.yml .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline