FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY CSharp-Identity-Provider.csproj ./
RUN dotnet restore CSharp-Identity-Provider.csproj
COPY Program.cs IdentityCore.cs ./
RUN dotnet publish CSharp-Identity-Provider.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    IDENTITY_DATA_PATH=/data/users.json
RUN mkdir -p /data && chown -R app:app /app /data
COPY --from=build --chown=app:app /out/ ./
USER app
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["dotnet", "SkyIdentity.dll"]
