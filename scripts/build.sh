#!/bin/bash
set -euo pipefail

# Define your GitHub token and version file
GITHUB_TOKEN=${GITHUB_TOKEN:-default_value}
VERSION_FILE="$(pwd)/scripts/dev.version"

# Function to get the latest version tag from Git
get_latest_version() {
  # Get the latest version tag from Git
  latest_version=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")

  # Extract major, minor, and patch versions
  major_version=$(echo "$latest_version" | cut -d. -f1 | sed 's/[^0-9]*//g')
  minor_version=$(echo "$latest_version" | cut -d. -f2 | sed 's/[^0-9]*//g')
  patch_version=$(echo "$latest_version" | cut -d. -f3 | sed 's/[^0-9]*//g')

  echo "$major_version $minor_version $patch_version"
}

# Function to update the version file
update_version_file() {
  echo "$1" > "$VERSION_FILE"
}

# Function to commit and push the tag to the Git repository
commit_tag_push() {
  local build_version=$1

  git pull
  git add .
  git commit -am "New Build $build_version"
  git push origin master

  git tag -a "$build_version" -m "New Build $build_version"
  git push origin "$build_version"
}

# Function to build and release a new development version
build_dev() {
  local current_version=($(get_latest_version))
  local major_version=${current_version[0]}
  local minor_version=${current_version[1]}
  local patch_version=${current_version[2]}
  local next_patch_version=$((patch_version + 1))

  local build_version=$(echo "$major_version.$minor_version.$next_patch_version")

  echo "Building and releasing new development version: $build_version"
  commit_tag_push "$build_version"
  update_version_file "$build_version"
}

# Function to build and release a new minor version
build_minor_release() {
  local current_version=($(get_latest_version))
  local major_version=${current_version[0]}
  local minor_version=${current_version[1]}
  local next_minor_version=$((minor_version + 1))

  local build_version=$(echo "$major_version.$next_minor_version.0")

  echo "Building and releasing new minor version: $build_version"
  commit_tag_push "$build_version"
  update_version_file "$build_version"
}

# Function to build and release a new major version
build_major_release() {
  local current_version=($(get_latest_version))
  local major_version=${current_version[0]}
  local next_major_version=$((major_version + 1))

  local build_version=$(echo "$next_major_version.0.0")

  echo "Building and releasing new major version: $build_version"
  commit_tag_push "$build_version"
  update_version_file "$build_version"
}

# Main script
git config --global user.name "Daniel Moloney"
git config --global user.email "24286010+DanMolz@users.noreply.github.com"

if [ "$1" = "--dev" ]; then
  build_dev
elif [ "$1" = "--minor" ]; then
  build_minor_release
elif [ "$1" = "--major" ]; then
  build_major_release
fi