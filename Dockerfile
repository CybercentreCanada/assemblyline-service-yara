FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH yara_.yara_.Yara

RUN apt-get update && apt-get install -y \
  git \
  libssl-dev \
  libmagic-dev \
  automake \
  libtool \
  make \
  gcc

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v3.11.0.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-3.11.0
RUN ./bootstrap.sh
RUN ./configure --enable-magic --enable-dotnet --with-crypto
RUN make
RUN make install

RUN pip install \
  yara-python \
  gitpython

# Create update directory
RUN mkdir -p /mount/updates

# Switch to assemblyline user
USER assemblyline

# Copy Yara service code
WORKDIR /opt/al_service
COPY . .
