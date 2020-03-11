FROM cccs/assemblyline-service-yara:latest

# Build the tagcheck container as a variant of the yara container where the additional
# tagcheck service code has been copied in
RUN mkdir -p /opt/al_service/tagcheck
COPY ./tagcheck ./tagcheck
RUN rm tagcheck/Dockerfile

# Over write the service path/manafest
ENV SERVICE_PATH tagcheck.tagcheck.TagCheck
RUN mv tagcheck/service_manifest.yml .

