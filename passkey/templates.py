"""Secret templates for common services."""

import json
from pathlib import Path

from .dirs import ensure_data_dir


def _get_templates_dir() -> Path:
    return ensure_data_dir() / "templates"


# --- Built-in templates ---

BUILTIN_TEMPLATES: list[dict] = [
    {
        "name": "github",
        "description": "GitHub personal access token or OAuth app",
        "fields": [
            {"name": "GITHUB_TOKEN", "description": "Personal access token (ghp_...)", "secret": True, "generate": True},
            {"name": "GITHUB_CLIENT_ID", "description": "OAuth app client ID", "secret": False},
            {"name": "GITHUB_CLIENT_SECRET", "description": "OAuth app client secret", "secret": True, "generate": True},
        ],
    },
    {
        "name": "aws",
        "description": "AWS IAM credentials",
        "fields": [
            {"name": "AWS_ACCESS_KEY_ID", "description": "IAM access key ID", "secret": False},
            {"name": "AWS_SECRET_ACCESS_KEY", "description": "IAM secret access key", "secret": True, "generate": True},
            {"name": "AWS_SESSION_TOKEN", "description": "Temporary session token (optional)", "secret": True},
        ],
    },
    {
        "name": "slack",
        "description": "Slack app / bot tokens",
        "fields": [
            {"name": "SLACK_BOT_TOKEN", "description": "Bot user OAuth token (xoxb-...)", "secret": True},
            {"name": "SLACK_APP_TOKEN", "description": "App-level token (xapp-...)", "secret": True},
            {"name": "SLACK_SIGNING_SECRET", "description": "Signing secret for request verification", "secret": True, "generate": True},
        ],
    },
    {
        "name": "openai",
        "description": "OpenAI API access",
        "fields": [
            {"name": "OPENAI_API_KEY", "description": "API key (sk-...)", "secret": True},
        ],
    },
    {
        "name": "stripe",
        "description": "Stripe payment processing",
        "fields": [
            {"name": "STRIPE_SECRET_KEY", "description": "Secret API key (sk_...)", "secret": True},
            {"name": "STRIPE_PUBLISHABLE_KEY", "description": "Publishable key (pk_...)", "secret": False},
            {"name": "STRIPE_WEBHOOK_SECRET", "description": "Webhook endpoint signing secret (whsec_...)", "secret": True, "generate": True},
        ],
    },
    {
        "name": "vercel",
        "description": "Vercel deployment token",
        "fields": [
            {"name": "VERCEL_TOKEN", "description": "API token", "secret": True},
        ],
    },
    {
        "name": "postgres",
        "description": "PostgreSQL connection",
        "fields": [
            {"name": "POSTGRES_HOST", "description": "Database hostname", "secret": False},
            {"name": "POSTGRES_PORT", "description": "Database port (default: 5432)", "secret": False},
            {"name": "POSTGRES_DB", "description": "Database name", "secret": False},
            {"name": "POSTGRES_USER", "description": "Database username", "secret": False},
            {"name": "POSTGRES_PASSWORD", "description": "Database password", "secret": True, "generate": True},
        ],
    },
    {
        "name": "mysql",
        "description": "MySQL connection",
        "fields": [
            {"name": "MYSQL_HOST", "description": "Database hostname", "secret": False},
            {"name": "MYSQL_PORT", "description": "Database port (default: 3306)", "secret": False},
            {"name": "MYSQL_DATABASE", "description": "Database name", "secret": False},
            {"name": "MYSQL_USER", "description": "Database username", "secret": False},
            {"name": "MYSQL_PASSWORD", "description": "Database password", "secret": True, "generate": True},
        ],
    },
]


def list_templates() -> list[dict]:
    """List all available templates (built-in + custom).

    Custom templates with the same name as a built-in override it.

    Returns:
        List of template dicts, sorted by name.
    """
    templates = {t["name"]: t for t in BUILTIN_TEMPLATES}

    # Load custom templates, overriding built-ins
    custom_dir = _get_templates_dir()
    if custom_dir.exists():
        for f in custom_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if "name" in data and "fields" in data:
                    templates[data["name"]] = data
            except (json.JSONDecodeError, KeyError):
                continue

    return sorted(templates.values(), key=lambda t: t["name"])


def get_template(name: str) -> dict | None:
    """Get a specific template by name.

    Args:
        name: Template name (e.g., "github")

    Returns:
        Template dict, or None if not found.
    """
    templates = {t["name"]: t for t in list_templates()}
    return templates.get(name)


def save_custom_template(template: dict) -> None:
    """Save a custom template to disk.

    Secret values are stripped — only field names and metadata are saved.

    Args:
        template: Template dict with 'name', 'description', and 'fields'
    """
    custom_dir = _get_templates_dir()
    custom_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Strip any secret values that might have been included
    cleaned = {
        "name": template["name"],
        "description": template.get("description", ""),
        "fields": [
            {k: v for k, v in field.items() if k != "value"}
            for field in template.get("fields", [])
        ],
    }

    path = custom_dir / f"{cleaned['name']}.json"
    path.write_text(json.dumps(cleaned, indent=2))
    path.chmod(0o600)
