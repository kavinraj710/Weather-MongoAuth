FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

# Fix port for AWS ALB
EXPOSE 80
ENV ASPNETCORE_URLS=http://+:80
ENV ASPNETCORE_ENVIRONMENT=Production

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

COPY ["MongoAuth/MongoAuth.csproj", "MongoAuth/"]
COPY ["MongoAuth.Shared/MongoAuth.Shared.csproj", "MongoAuth.Shared/"]

RUN dotnet restore "./MongoAuth/MongoAuth.csproj"

COPY . .
WORKDIR "/src/MongoAuth"

RUN dotnet build "./MongoAuth.csproj" -c $BUILD_CONFIGURATION -o /app/build

# Publish stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./MongoAuth.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# Final stage
FROM base AS final
WORKDIR /app

COPY --from=publish /app/publish .

ENTRYPOINT ["dotnet", "MongoAuth.dll"]