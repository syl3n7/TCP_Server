# Use the official .NET SDK image as the build image
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build-env
WORKDIR /app

# Copy csproj and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy the remaining source code
COPY . ./

# Build the application
RUN dotnet publish -c Release -o out

# Build the runtime image
FROM mcr.microsoft.com/dotnet/runtime:9.0
WORKDIR /app
COPY --from=build-env /app/out .

# Install MySqlConnector dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libc6 \
       libgcc1 \
       libgssapi-krb5-2 \
       libssl1.1 \
       libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Create directory for logs
RUN mkdir -p /app/logs \
    && chmod 777 /app/logs

# Define environment variables (without default values for sensitive data)
ENV DB_SERVER=localhost \
    DB_PORT=3306 \
    DB_NAME=chatapp \
    DB_USER=root

# Create an entrypoint script to handle database configuration at runtime
RUN echo '#!/bin/bash\n\
\n\
# Check if required environment variables are set\n\
if [ -z "$DB_PASSWORD" ]; then\n\
  echo "Error: DB_PASSWORD environment variable must be set"\n\
  exit 1\n\
fi\n\
\n\
# Generate db_config.json from environment variables\n\
echo "{\n\
  \"Server\": \"$DB_SERVER\",\n\
  \"Port\": $DB_PORT,\n\
  \"Database\": \"$DB_NAME\",\n\
  \"Username\": \"$DB_USER\",\n\
  \"Password\": \"$DB_PASSWORD\"\n\
}" > /app/db_config.json\n\
\n\
echo "Database configuration created successfully"\n\
\n\
# Start the application\n\
exec dotnet Server_.dll\n\
' > /app/entrypoint.sh \
&& chmod +x /app/entrypoint.sh

# Expose the port
EXPOSE 8443 

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]