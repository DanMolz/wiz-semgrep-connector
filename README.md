# Wiz Semgrep Connector

## Overview

The Wiz Semgrep Connector is a Go application that integrates with the Semgrep AppSec Platform and Wiz API to fetch security findings and upload them to Wiz. The application runs on a configurable interval, fetching findings from Semgrep, transforming them, and uploading them to Wiz.

## Configuration

The application requires the following environment variables to be set:

- `WIZ_API_ENDPOINT`: The endpoint for the Wiz API.
- `WIZ_CLIENT_ID`: The client ID for Wiz authentication.
- `WIZ_CLIENT_SECRET`: The client secret for Wiz authentication.
- `SEMGREP_API_TOKEN`: The API token for Semgrep authentication.
- `SEMGREP_DEPLOYMENT`: The Semgrep deployment identifier.
- `FETCH_INTERVAL`: The interval (in hours) at which the application fetches findings from Semgrep.

You can set these environment variables in a `.env` file in the root directory of the project:

```env
WIZ_API_ENDPOINT=https://api.<region>.app.wiz.io/graphql
WIZ_CLIENT_ID=your_wiz_client_id
WIZ_CLIENT_SECRET=your_wiz_client_secret
SEMGREP_API_TOKEN=your_semgrep_api_token
SEMGREP_DEPLOYMENT=your_semgrep_deployment
FETCH_INTERVAL=24
```

## Docker

You can also deploy the the connector as a docker container

```bash
docker run --name wiz-semgrep-connector -d \
-e WIZ_API_ENDPOINT=https://api.<region>.app.wiz.io/graphql \
-e WIZ_CLIENT_ID=your_wiz_client_id \
-e WIZ_CLIENT_SECRET=your_wiz_client_secret \
-e SEMGREP_API_TOKEN=your_semgrep_api_token \
-e SEMGREP_DEPLOYMENT=your_semgrep_deployment \
-e FETCH_INTERVAL=24 \
danielmoloney/wiz-semgrep-connector:latest
```