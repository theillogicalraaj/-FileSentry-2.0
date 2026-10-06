# Security Notes

FileSentry is a defensive analysis platform. Uploaded files are considered hostile input.

## Trust boundary

The upload endpoint is an untrusted boundary. The application must never interpret an uploaded sample as an executable program.

## Required deployment hardening

1. Use a strong random `JWT_SECRET` outside development.
2. Put the API behind TLS.
3. Keep the quarantine directory on a volume mounted with the least privileges possible.
4. Run the API as a non-root user in production.
5. Put deeper parsers (YARA, PE/Office parsers, decompression, sandbox integrations) in isolated worker containers.
6. Add object retention and deletion policies before storing production evidence.
7. Add audit logging and RBAC for multi-user or enterprise deployment.
8. Never point FileSentry at malware samples on a production workstation. Use an isolated analysis network.

## Threat model

The application is designed to resist common web-upload mistakes: path traversal through filenames, shell execution, unrestricted body size, and unauthenticated analysis endpoints. It is not a malware sandbox and should not be advertised as one.
