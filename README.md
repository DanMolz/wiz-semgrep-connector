# Wiz Semgrep Connector

## Overview

The Wiz Semgrep Connector is a Go application that integrates with the Semgrep AppSec Platform and Wiz API to fetch security findings and upload them to Wiz. The application runs on a configurable interval, fetching findings from Semgrep, transforming them, and uploading them to Wiz.

## Configuration
Here is the current set of supported variables:

|             NAME                           |   REQUIRED   |    DEFAULT             |                                  DESCRIPTION                                   |
|--------------------------------------------|--------------|------------------------|--------------------------------------------------------------------------------|
| `MODE`                                     | Optional     |    agent               | Configure 'scheduled' or 'agent' mode.                                         |
| `WIZ_API_ENDPOINT`                         | Yes          |    ""                  | Wiz API Endpoint. Format: https://api.<region>.app.wiz.io/graphql              |
| `WIZ_CLIENT_ID`                            | Yes          |    ""                  | Wiz client ID for authentication.                                              |
| `WIZ_CLIENT_SECRET`                        | Yes          |    ""                  | Wiz Client secret for authentication.                                          |
| `SEMGREP_API_TOKEN`                        | Yes          |    ""                  | Semgrep API token for authentication.                                          |
| `SEMGREP_DEPLOYMENT`                       | Yes          |    ""                  | Semgrep deployment identifier.                                                 |
| `TARGET_REPO`                              | Optional     |    ""                  | Repository which will be used to collect findings.                             |
| `FETCH_INTERVAL`                           | Optional     |    24                  | Interval (in hours) at which the application fetches findings from Semgrep.    |

You can set these environment variables in a `.env` file in the root directory of the project:

## Docker (Scheduled)

You can also deploy the the connector as a docker container

```bash
docker run --name wiz-semgrep-connector -d \
-e MODE=scheduled \
-e WIZ_API_ENDPOINT=https://api.<region>.app.wiz.io/graphql \
-e WIZ_CLIENT_ID=your_wiz_client_id \
-e WIZ_CLIENT_SECRET=your_wiz_client_secret \
-e SEMGREP_API_TOKEN=your_semgrep_api_token \
-e SEMGREP_DEPLOYMENT=your_semgrep_deployment \
-e FETCH_INTERVAL=24 \
danielmoloney/wiz-semgrep-connector:latest
```

## GitHub (Agent)
Create a Github Workflow using the below configuration.
```
on:
  workflow_dispatch: {}
  pull_request: {}
  push:
    branches:
    - main
    - master
  schedule:
  # random HH:MM to avoid a load spike on GitHub Actions at 00:00
  - cron: 19 20 * * *
name: Wiz/Semgrep Collector
jobs:
  collector:
    name: collector/ci
    runs-on: ubuntu-20.04
    env:
      MODE: agent
      WIZ_API_ENDPOINT: https://api.<region>.app.wiz.io/graphql
      WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
      WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
      SEMGREP_API_TOKEN: ${{ secrets.SEMGREP_API_TOKEN }}
      SEMGREP_DEPLOYMENT: your_semgrep_deployment
    container:
      image: danielmoloney/wiz-semgrep-connector
    steps:
    - uses: actions/checkout@v4
    - run: collector ci
```