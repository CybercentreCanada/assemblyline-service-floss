ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH floss.floss.Floss

USER root

# python-levenshtein gives a faster fuzzywuzzy
RUN apt-get update && apt-get install -y python3-levenshtein unzip curl && rm -rf /var/lib/apt/lists/*

# Get the latest FLOSS binary
RUN curl -L https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip -o floss.zip \
    && unzip floss.zip -d /opt \
    && chmod +x /opt/floss \
    && rm floss.zip

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
