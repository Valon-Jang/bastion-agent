# Security Policy

## Supported status

The first public source snapshot is a release candidate intended for review and
controlled testing. It is not a signed production release.

## Reporting a vulnerability

Do not include credentials, private source code, internal paths, personal data,
or exploit details in a public issue. Use GitHub private vulnerability reporting
when it is available for this repository.

## Runtime boundary

The company-direct profile executes local commands with the current Windows
user's permissions. It does not provide OS-level filesystem or network
isolation. Test with non-sensitive data and obtain organizational approval
before workplace deployment.
