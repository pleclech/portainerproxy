# Portainer Docker Proxy

This is a Go program that creates an HTTP/HTTPS proxy server for Portainer and Docker. The proxy server listens on a specified address and port and forwards requests to the appropriate service.

## Usage

To use the program, you'll need to provide the following command-line flags:

- `--portainer`: The URL of the Portainer instance to proxy.
- `--host`: The Docker host to proxy.
- `--address`: The address and port to listen on. Defaults to `:8080`.
- `--https`: Whether to use HTTPS. If set, you must also provide `--cert` and `--key`.
- `--cert`: The path to the certificate file if using HTTPS.
- `--key`: The path to the key file if using HTTPS.
- `--portainer-service-name`: The name of the Portainer service if running in Docker.

If Portainer and the proxy are running in Docker, you can specify the name of the Portainer service using the `--portainer-service-name` flag.

Here's an example command to start the proxy server:

portproxy --portainer http://localhost:9000 --host unix:///var/run/docker.sock --address :8080

This command starts the proxy server listening on port 8080 and forwards requests to Portainer running on `http://localhost:9000` and Docker running on `unix:///var/run/docker.sock`.

If you want to use HTTPS, you can specify the `--https` flag and the paths to the certificate and key files:

portproxy --portainer http://localhost:9000 --host unix:///var/run/docker.sock --address :8443 --https --cert /path/to/cert.pem --key /path/to/key.pem


This command starts the proxy server listening on port 8443 using HTTPS and forwards requests to Portainer and Docker as before.

If Portainer and the proxy are running in Docker, you can specify the name of the Portainer service using the `--portainer-service-name` flag:

portproxy --portainer http://portainer:9000 --host unix:///var/run/docker.sock --address :8080 --portainer-service-name portainer

The commands `start, exec, attach,` and `wait` are proxied directly to the Docker host, but only if the user has the necessary permissions in Portainer.

## Using the Portainer Docker Proxy with the Docker CLI

To use the Portainer Docker Proxy with the Docker CLI, you can specify custom parameters using the `DOCKER_HOST` environment variable or the `-host` flag. The custom parameters are used to specify the Portainer username, API key, and environment ID.

Here's how to use the custom parameters with the Docker CLI:

1. Set the `DOCKER_HOST` environment variable to the address and port of the proxy server, followed by the custom parameters.

    `DOCKER_HOST=tcp://proxy address:proxy port/--user='username in portainer'&apikey='apikey for using portainer api'&envid='the id of your docker env in portainer'--/`

    Note that the custom parameters are enclosed in `/--` and `--/`.

    The custom parameters are:

    - `user`: The Portainer username.
    - `apikey`: The API key for using the Portainer API.
    - `envid`: The ID of your Docker environment in Portainer.

2. Run the `docker run` command as you normally would, specifying the image you want to run.

Here's an example command that includes the custom parameters:

```DOCKER_HOST=tcp://localhost:8080/--user=foo&apikey=ptr_xyz&envid=6--/ docker run -d nginx```

