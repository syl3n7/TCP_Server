# Use the official .NET SDK image as the build image
FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build-env
WORKDIR /app

# Copy csproj and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy the remaining source code
COPY . ./

# Build the application
RUN dotnet publish -c Release -o out

# Build the runtime image
FROM mcr.microsoft.com/dotnet/runtime:7.0
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

# Environment variables for database configuration
ENV DB_SERVER=localhost \
    DB_PORT=3306 \
    DB_NAME=chatapp \
    DB_USER=root \
    DB_PASSWORD=password

# Change server binding to accept connections from outside the container
# In your code: TcpListener server = new TcpListener(IPAddress.Parse("127.0.0.1"), 12345);
# Should be: TcpListener server = new TcpListener(IPAddress.Any, 12345);
# You'll need to make this change in your Program.cs file

# Create a db_config.json file using environment variables
RUN echo '{\n\
  "Server": "'$DB_SERVER'",\n\
  "Port": '$DB_PORT',\n\
  "Database": "'$DB_NAME'",\n\
  "Username": "'$DB_USER'",\n\
  "Password": "'$DB_PASSWORD'"\n\
}' > /app/db_config.json

# Create an entrypoint script to handle database configuration at runtime
RUN echo '#!/bin/bash\n\
# Generate db_config.json from environment variables\n\
echo "{\n\
  \"Server\": \"$DB_SERVER\",\n\
  \"Port\": $DB_PORT,\n\
  \"Database\": \"$DB_NAME\",\n\
  \"Username\": \"$DB_USER\",\n\
  \"Password\": \"$DB_PASSWORD\"\n\
}" > /app/db_config.json\n\
\n\
# Start the application\n\
exec dotnet Server_.dll\n\
' > /app/entrypoint.sh \
&& chmod +x /app/entrypoint.sh

# Expose the port
EXPOSE 12345

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]