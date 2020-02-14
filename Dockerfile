FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH floss.floss.Floss

# Get the latest FLOSS binary
RUN curl -L https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-GNU.Linux.zip -o /tmp/floss.zip
RUN unzip /tmp/floss.zip -d /tmp
WORKDIR /tmp/
COPY /tmp/floss /opt/floss
RUN chown assemblyline /opt/floss

# Cleanup
RUN rm /tmp/floss /tmp/floss.zip

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .