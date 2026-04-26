![lolkek](image.png)


`awscan` is a lightweight AWS security scanner.

It performs baseline checks for:
- S3
- IAM
- Security Groups
- VPC / Subnets / Routes / IGW

Results are shown in the console and can be saved as JSON (`report.json`).

## Current Setup

- Primary execution: **GitHub Actions** (CI/CD).
- Local execution: `.env` for local testing and manual runs.

## Local Run (for testing)

1. Create `.env` from `.env.example`.
2. Fill in AWS variables.
3. Run:

```bash
./bin/awscan --json-out report.json
```

Examples:

```bash
# Exit with code 1 if HIGH/CRITICAL findings exist
./bin/awscan --json-out report.json --fail-on HIGH

# Run tests
python -m unittest discover -s tests -p "test_*.py"
```

Important: `.env` is for local runs only.  
In CI, values are loaded from GitHub `Secrets/Variables`.

## GitHub Actions (primary flow)

Workflow: [`.github/workflows/main.yml`](./.github/workflows/main.yml)

Triggers:
- `push` to `main`
- manual run via `workflow_dispatch`

Job steps:
1. Install dependencies
2. Run unit tests
3. Run `awscan` with `--json-out report.json --fail-on HIGH`
4. Publish a summary in GitHub Actions
5. Upload `report.json` as an artifact
6. Send status + report to Telegram (if bot token/chat ID are configured)

## GitHub Configuration

### Secrets
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

### Variables
- `AWSCAN_AWS_MAX_ATTEMPTS`
- `AWSCAN_AWS_RETRY_MODE`
- `AWSCAN_AWS_CONNECT_TIMEOUT`
- `AWSCAN_AWS_READ_TIMEOUT`

## Where to Find Results

After a workflow run:
- **Actions** tab → specific run: logs and summary
- **Artifacts** section: `awscan-report` (`report.json`)
- Telegram: status message + report file
