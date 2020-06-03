FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH floss.floss.Floss

USER root

#python-levenshtein gives a faster fuzzywuzzy
RUN apt-get update && apt-get install -y python-levenshtein unzip curl && rm -rf /var/lib/apt/lists/*

# Get the latest FLOSS binary
RUN curl -L https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-GNU.Linux.zip -o floss.zip \
 && unzip floss.zip -d /opt \
 && chmod +x /opt/floss \
 && rm floss.zip

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline