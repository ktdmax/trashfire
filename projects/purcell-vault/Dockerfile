# BUG-none: Multi-stage build looks reasonable but has several issues noted below

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY PurcellVault.csproj .
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release -o /app/publish

# Runtime stage
# RH-007: This looks like it might be using the SDK image for runtime (which would be a vuln), but it correctly uses the ASP.NET runtime image (Safe: proper multi-stage build with runtime-only image)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# BUG-none: Running as root in container — should use non-root user
# (This is a known Docker security issue but not numbered as a unique bug since it's a container config concern)

COPY --from=build /app/publish .

# BUG-none: appsettings.json with hardcoded secrets baked into image (covered by BUG-0002, BUG-0006)

# BUG-none: No HEALTHCHECK instruction — container orchestrator can't verify app health

EXPOSE 8080

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
# BUG-0008 (cross-ref): DetailedErrors set to true in production Docker image (CWE-489, CVSS 3.6, LOW, Tier 3)
ENV DetailedErrors=true

ENTRYPOINT ["dotnet", "PurcellVault.dll"]
