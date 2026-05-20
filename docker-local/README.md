# docker-local

Docker Compose configuration to support local testing with AWS services.

## Prerequisites

- Docker

## Usage

1. Start the DynamoDB container in the background: `docker compose -f docker-local/docker-compose.yml up -d`
2. Update config.yaml for DynamoDB
   - `db.table: kt_local`
   - `db.parallel: 2`
3. Run the server
   - `AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_ENDPOINT_URL=http://localhost:8000 AWS_REGION=local-kt go run github.com/signalapp/keytransparency/cmd/kt-server -config ./example/config.yaml`
4. Test with kt-client
5. Stop the server
6. Stop the container
   - `docker compose -f docker-local/docker-compose.yml down`
