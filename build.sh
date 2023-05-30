# MIT License
# 
# Copyright (c) 2023 pleclech
# Github: https://github.com/pleclech
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#!/bin/bash

# Build script for multiple platforms

declare -l user="pleclech"
declare -l outputDir="build"
declare -l executable="portproxy"

declare -l release="false"
declare -l version="0.0.0"

declare -l image="false"
declare -l push="false"

declare -l colored="true"

declare -l clean="false"

# List of target platforms
declare -a platforms=("linux/amd64" "linux/arm64" "windows/amd64" "darwin/amd64")

declare infoColor="\033[0;36m"
declare errorColor="\033[0;31m"
declare noColor="\033[0m"
declare successColor="\033[0;32m"

info() {
    if [ "$colored" == "true" ]; then
        echo -e "${infoColor}$1${noColor}"
    else
        echo "$1"
    fi
}

error() {
    if [ "$colored" == "true" ]; then
        echo -e "${errorColor}$1${noColor}"
    else
        echo "$1"
    fi
}

success() {
    if [ "$colored" == "true" ]; then
        echo -e "${successColor}$1${noColor}"
    else
        echo "$1"
    fi
}

get_colored() {
    if [ "$1" != "true" ] && [ "$1" != "false" ]; then
        error "Invalid option for colored: <$1> must be true or false" >&2
        exit 1
    else
        echo "$1"
    fi
}

getCurrentOS() {
    case "$(uname -s)" in
        Darwin*)
            echo "darwin"
            ;;
        Linux*)
            echo "linux"
            ;;
        CYGWIN*|MINGW32*|MSYS*|MINGW*)
            echo "windows"
            ;;
        *)
            error "Unknown OS detected: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

getCurrentArch() {
    case "$(uname -m)" in
        x86_64*|amd64*)
            echo "amd64"
            ;;
        arm64*|aarch64*)
            echo "arm64"
            ;;
        *)
            error "Unknown architecture detected: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

showUsage() {
    info "Usage: $0 [-r|--release] [-v version | --version=version] [-e executable-name | --executable=executable-name] [-b build-path | --build=build-path] [-i | --image build a docker image] [-p | --push push image to docker hub] [-u | --user user for docker hub] [--clean] [--platforms=platform_1,..,platform_n]" >&2
    exit 1
}

while getopts ":b:c:e:r:i:p:v:u:-:" opt; do
    case ${opt} in
        b)
            outputDir=$OPTARG
            ;;
        c)
            colored=$(get_colored "$OPTARG")
            ;;
        e)
            executable=$OPTARG
            ;;
        r)
            release="true"
            ;;
        i)
            image="true"
            ;;
        p)
            push="true"
            ;;
        v)
            version=$OPTARG
            ;;
        u)
            user=$OPTARG
            ;;
        -)
            case "${OPTARG}" in
                build=*)
                    outputDir=${OPTARG#*=}
                    ;;
                executable=*)
                    executable=${OPTARG#*=}
                    ;;
                release)
                    release="true"
                    ;;
                image)
                    image="true"
                    ;;
                push)
                    push="true"
                    ;;
                user=*)
                    user=${OPTARG#*=}
                    ;;
                version=*)
                    version=${OPTARG#*=}
                    ;;
                platforms=*)
                    IFS=',' read -r -a platforms <<< "${OPTARG#*=}"
                    ;;
                clean)
                    clean=true
                    ;;
                help)
                    showUsage
                    ;;
                *)
                    error "Invalid option: --${OPTARG}" >&2
                    showUsage
                    ;;
            esac
            ;;
        \?)
            error "Invalid option: -$OPTARG" >&2
            showUsage
            ;;
    esac
done

# Create the output directory
# capture the output of the mkdir command
# and print it only if there is an error
o=$(mkdir -p "$outputDir" 2>&1)
if [ $? -ne 0 ]; then
    error "$o"
    exit 1
fi

# If the clean flag is set, remove the output directory
if [ "$clean" == "true" ]; then
    info "Cleaning output directory: $outputDir"
    rm -f "$outputDir"/*
fi

declare imagePrefix=""

declare -a ldFlags=("-X main.version=$version")

if [ "$release" == "true" ]; then
    ldFlags+=("-s -w")
else
    imagePrefix="dev-"
fi

export CGO_ENABLED=0
go mod tidy

# Loop through the platforms and build them
for platform in "${platforms[@]}"; do
    # Extract the OS and architecture from the platform string
    IFS='/' read -r -a platformArr <<< "$platform"
    os="${platformArr[0]}"
    arch="${platformArr[1]}"

    # Set the environment variables
    export GOOS="$os"
    export GOARCH="$arch"

    # Define the output file name
    outputFile="$outputDir/$executable-$os-$arch"
    if [ $os = "windows" ]; then
	    outputFile+='.exe'
    fi


    info "Building $outputFile version $version"

    # Build the executable
    # capture the output of the build command
    o=$(go build -o "$outputFile" -ldflags "${ldFlags[*]}" main.go)
    if [ $? -ne 0 ]; then
        error "$o"
        exit 1
    fi
    info "$o"

    # Print the build information
    success "done"
done

if [ "$release" != "true" ]; then
    outputFile="$outputDir/$executable"

    declare -a ldFlags=()

    # Set the version
    ldFlags+=("-X main.version=$version")


    info "Building $outputFile version $version"

    # Build the executable
    # capture the output of the build command
    # and print it only if there is an error
    o=$(go build -o "$outputDir/$executable" -ldflags "${ldFlags[*]}" main.go 2>&1)
    if [ $? -ne 0 ]; then
        error "$o"
        exit 1
    fi

    info "$o"
    success "done"
fi

# Push the image if push is true
if [ "$image" == "true" ]; then
    # build image for each platform but windows
    for platform in "${platforms[@]}"
    do
        IFS='/' read -r -a platformArr <<< "$platform"
        os="${platformArr[0]}"
        arch="${platformArr[1]}"

        if [ $os = "windows" ]; then
            continue
	    fi

        image="ghcr.io/${user}/${imagePrefix}portproxy:${version}-${os}-${arch}"
        
        info "Building image for ${image}"
        declare -a options=()

        if [ "$push" == "true" ]; then
            options+=("--push")
        fi

        o=$(DOCKER_BUILDKIT=1 docker buildx build --platform ${platform}  -t "${image}" --build-arg OS=${os} --build-arg ARCH=${arch} --file ./build.Dockerfile "${options[@]}" . 2>&1)
        if [ $? -ne 0 ]; then
            error "$o"
            exit 1
        fi

        info "$o"
        success "done"
    done
fi

# # Push the image if push is true
# if [  "$push" == "true" ]; then
#     # push image for each platform but windows
#     for platform in "${platforms[@]}"
#     do
#         IFS='/' read -r -a platformArr <<< "$platform"
#         os="${platformArr[0]}"
#         arch="${platformArr[1]}"

#         if [ $os = "windows" ]; then
#             continue
#         fi

#         image="${user}/portproxy:${version}-${os}-${arch}"
        
#         info "Pushing image ${image}"

#         o=$(docker push "${image}" 2>&1)
#         if [ $? -ne 0 ]; then
#             error "$o"
#             exit 1
#         fi

#         info "$o"
#         success "done"
#     done
# fi