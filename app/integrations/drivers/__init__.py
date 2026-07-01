"""Integration driver registry."""
from app.integrations.drivers import aws_cloudtrail, google_workspace

# Each entry is a driver module conforming to the IntegrationDriver protocol
DRIVERS: dict[str, object] = {
    "aws_cloudtrail": aws_cloudtrail,
    "google_workspace": google_workspace,
}
