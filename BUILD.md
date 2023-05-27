## Building and Pushing a Go Project

To build and push a Go project, you can use the `build.sh` script provided in the project directory. The script uses Docker to build the project and push the resulting image to a Docker registry.

### Prerequisites

Before you begin, make sure you have the following prerequisites installed on your system:

- Docker (optional if you're not building a Docker image)
- Go

### Using the Build Script

The `build.sh` script provides several options for building and pushing your project. Here's a list of the available options:

- `-r` or `--release`: Build the project for multiple platforms and create release binaries.
- `-v` or `--version`: Set the version number for the project.
- `-e` or `--executable`: Set the name of the executable file.
- `-b` or `--build`: Set the output directory for the build.
- `-i`: Build a Docker image for the project.
- `-p`: Push the Docker image to Docker Hub.
- `-u`: Set the Docker Hub username.

To build the project, run the following command:

```shell
./build.sh --release -v 1.0.0 -e myproject -b build
```
This command builds the project for multiple platforms and creates release binaries with the version number `1.0.0`. The executable file is named `myproject`, and the output directory is `build`.

To build a Docker image for the project, run the following command:
./build.sh -i -v 1.0.0 -u myusername

this command builds a Docker image for the project with the version number 1.0.0 and the Docker Hub username myusername.

To push the Docker image to Docker Hub, run the following command:
./build.sh -i -p -v 1.0.0 -u myusername

This command builds a Docker image for the project with the version number `1.0.0`, the Docker Hub username `myusername`, and pushes the image to Docker Hub.