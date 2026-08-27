<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/shannon-banner-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="./assets/shannon-banner-light.png">
  <img src="./assets/shannon-banner-light.png" alt="Shannon, AI Pentester for Web Apps and APIs, by Keygraph" width="100%">
</picture>
</div>

# Shannon GitHub Action

Run [Shannon](https://github.com/KeygraphHQ/shannon), Keygraph's autonomous white-box AI pentester, from a GitHub Actions workflow. Shannon reads your source code, maps the attack surface, and exploits real vulnerabilities against a running target, then hands you a security assessment report. This action is a thin wrapper around the [`@keygraph/shannon`](https://www.npmjs.com/package/@keygraph/shannon) CLI.

## What you get

Every run uploads two artifacts:

- `shannon-report-<workspace>`: the Security Assessment Report (`.pdf` + `.md`) and `report.sarif`. The findings and how to fix them.
- `shannon-run-<workspace>`: scan log, agent logs, and other run files, for debugging (uploaded even on failure).

The job also writes a findings summary and artifact download links to the run's Summary tab, and the same as a plain-text footer at the end of the job log.

## Quick start

```yaml
name: Security scan
on:
  workflow_dispatch:

jobs:
  pentest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Shannon
        uses: KeygraphHQ/shannon-action@v1
        with:
          url: https://staging.example.com
          api-key: ${{ secrets.SHANNON_AI_API_KEY }}
```

`repo` defaults to the checked-out workspace, so this scans your code against the running `url`.

## Requirements

- A runner with Docker (daemon + `docker compose` v2) and access to Docker Hub. `ubuntu-latest` satisfies this out of the box.
- Node.js is set up for you.
- An AI provider API key (see [Credentials](#credentials)).
- A private repository. The action refuses to run on public ones: its report, logs, and artifacts can contain sensitive security findings about your application.

### Job timeout

A job gets 6 hours by default (`timeout-minutes` defaults to `360`), which is enough for Shannon.

## Examples

Ready-to-copy workflows in [`examples/`](./examples):

- [`pr-scan.yml`](./examples/pr-scan.yml): scan a pull request and block it on a demonstrated critical.
- [`release-scan.yml`](./examples/release-scan.yml): scan the staging deployment when a release is published, and send findings to code scanning.
- [`weekly-scan.yml`](./examples/weekly-scan.yml): scheduled weekly deep scan of a deployed environment.

## Credentials

Pass your provider key via `api-key` (it maps to `SHANNON_AI_API_KEY`). This works for the default Anthropic model and any plain-API-key provider:

```yaml
with:
  api-key: ${{ secrets.SHANNON_AI_API_KEY }}
```

Another provider: set `model` and pass that provider's key through the same input:

```yaml
with:
  model: openai:gpt-5
  api-key: ${{ secrets.OPENAI_API_KEY }}
```

Amazon Bedrock: authenticates with a bearer token plus a region, not a plain key:

```yaml
with:
  model: amazon-bedrock:us.anthropic.claude-sonnet-4-5-20250929-v1:0
  aws-bearer-token-bedrock: ${{ secrets.AWS_BEARER_TOKEN_BEDROCK }}
  aws-region: us-east-1
```

OpenAI-compatible gateway: point OpenAI at a proxy with `base-url`, and set the wire format if it isn't the default:

```yaml
with:
  model: openai:gpt-5
  base-url: https://my-gateway.example.com/v1
  openai-format: responses   # or omit for chat-completions
  api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `url` | yes | - | Target URL to test (the running application). |
| `repo` | | `${{ github.workspace }}` | Path to the source repo to analyze (white-box). |
| `config` | | - | Path to a Shannon YAML config (auth, scope, report options). |
| `workspace` | | `${{ github.run_id }}` | Named workspace; sets the output dir. Defaults to the run id so each run is isolated. Set a stable value to resume across runs (and to give matrix legs distinct names). |
| `model` | | `anthropic:claude-sonnet-4-6` | Model spec `<provider>:<model-id>` (`SHANNON_AI_MODEL`). |
| `base-url` | | - | Override the provider endpoint (`SHANNON_AI_BASE_URL`). |
| `openai-format` | | `chat-completions` | Wire format for an OpenAI-compatible gateway (`SHANNON_AI_OPENAI_FORMAT`): `chat-completions` or `responses`. Only with `model: openai:...` + `base-url`. |
| `api-key` | | - | LLM provider API key (`SHANNON_AI_API_KEY`) for any non-Bedrock provider, including the default Anthropic model. |
| `aws-bearer-token-bedrock` | | - | Amazon Bedrock bearer token (`AWS_BEARER_TOKEN_BEDROCK`). Required for `model: amazon-bedrock:...`. |
| `aws-region` | | - | AWS region for Bedrock (`AWS_REGION`). Required for `model: amazon-bedrock:...`. |
| `version` | | `2.6.0` | Version of the `@keygraph/shannon` npm package to run. |
| `pipeline-testing` | | `false` | Minimal prompts for fast pipeline testing. |
| `fail-on-severity` | | `none` | Fail the job if any exploited finding is at or above this severity: `none`, `low`, `medium`, `high`, `critical`. See [Pass / fail](#pass--fail). |
| `upload-sarif` | | `false` | Upload `report.sarif` (when produced) to GitHub code scanning. Requires `security-events: write`. |

## Outputs & artifacts

| Output | Description |
|---|---|
| `workspace-dir` | Absolute path to the scan workspace directory. |
| `report-pdf` | Path to `Security-Assessment-Report.pdf`, if produced. |
| `report-md` | Path to `Security-Assessment-Report.md`, if produced. |
| `sarif` | Path to `report.sarif`, if produced. |

The two uploaded artifacts are described under [What you get](#what-you-get). The run folder excludes the target's saved auth session (`auth-state.json`) so cookies never leave the runner. Artifact names must be unique within a run, so if you use a matrix, give each leg a distinct `workspace`.

## Pass / fail

The job passes only on a complete assessment: one where every vulnerability class was assessed. It fails when:

- the scan produced no report, or
- some class could not be assessed (a partial run; no findings for a class we never checked is not a clean result).

It does not fail merely because vulnerabilities were found. To also fail on demonstrated impact, set `fail-on-severity`:

```yaml
with:
  fail-on-severity: high   # fail if any exploited finding is high or critical
```

This gate counts only findings Shannon actually exploited (`status: exploited`). These are proven, not suspected, so it rarely fires on false positives. Severities rank `critical > high > medium > low`; a finding trips the job when its severity is at or above the threshold. Because it keys on exploited findings, it applies to exploit-mode scans only; an analysis-only scan (`exploit: false`) never trips it.

When the gate fails it reports how many findings crossed the threshold, not their details. If you use it to block PRs, also set `upload-sarif: true` so the findings appear in code scanning with their code locations, instead of leaving the author to dig through the report.

## SARIF / code scanning

Shannon writes `report.sarif` when your config enables exploitation and `report.sarif`. To push it to GitHub code scanning, set `upload-sarif: true` and grant the job `security-events: write`:

```yaml
permissions:
  security-events: write
# ...
with:
  config: .shannon/ci.yaml
  upload-sarif: true
  api-key: ${{ secrets.SHANNON_AI_API_KEY }}
```

If `upload-sarif` is `false` (the default) or no SARIF was produced, this step is skipped. The SARIF file is included in the report artifact either way.

## Editions

This action runs **Shannon Open Source**, the standalone pentester you run yourself. The **Keygraph platform** is the commercial product that runs an enhanced build of Shannon continuously and closes the full AppSec lifecycle around it — code analysis, finding management, automated remediation, and verification. See [Editions](https://github.com/KeygraphHQ/shannon#editions) for how the two compare.

## Security

Point Shannon at a staging or development environment you own. It actively exploits vulnerabilities, so it must never target production or systems you are not authorized to test.

## License

This action is licensed under the [Apache License 2.0](./LICENSE). The Shannon CLI it runs (`@keygraph/shannon`) is licensed separately under [AGPL-3.0](https://github.com/KeygraphHQ/shannon/blob/main/LICENSE).

<p align="center">
  <b>Built by <a href="https://keygraph.io">Keygraph</a></b>
</p>
