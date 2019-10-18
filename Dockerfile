FROM cccs/assemblyline-v3-service-base:latest

ENV SERVICE_PATH yara.yara.Yara

# Download the package file
#RUN pip3 download -d /tmp yara-pythpn
#RUN tar -zxf /tmp/yara-python-3.8.1.tar.gz -C /opt/al/support/yara
#RUN python3 setup.py build --enable-dotnet
#RUN python3 setup.py install

RUN pip install --user yara-python --global-option "build" --global-option "--enable-dotnet"
RUN pip install assemblyline_client

RUN apt-get update && apt-get install -y \
  git

# Copy Yara service code
WORKDIR /opt/al_service
COPY . .

# Copy the default 'rules.yar' file to '/opt/al/var/cache/signatures/'
COPY alv3_services_private/dev/alsvc_yara/rules.yar /opt/al/var/cache/signatures/rules.yar