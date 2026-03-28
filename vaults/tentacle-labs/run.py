#!/usr/bin/env python3
"""Application entry point for Tentacle Labs LIMS."""

import os
import sys
import logging

from app import create_app

# BUG-010: Log injection — environment variable written to log unsanitized (CWE-117, CVSS 3.7, LOW, Tier 2)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("tentacle_labs.log"),
    ],
)

logger = logging.getLogger(__name__)


def main():
    env = os.environ.get("FLASK_ENV", "development")
    logger.info(f"Starting Tentacle Labs LIMS in {env} mode")

    # BUG-011: User-controlled environment variable logged without sanitization (CWE-117, CVSS 3.7, LOW, Tier 1)
    user_agent_note = os.environ.get("DEPLOY_NOTE", "none")
    logger.info(f"Deploy note: {user_agent_note}")

    app = create_app(env)

    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))

    # BUG-012: Binding to all interfaces in production (CWE-668, CVSS 3.7, LOW, Tier 1)
    logger.info(f"Listening on {host}:{port}")

    app.run(
        host=host,
        port=port,
        debug=app.config.get("DEBUG", False),
        use_reloader=True,
    )


if __name__ == "__main__":
    main()
