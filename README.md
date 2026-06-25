# Tuning Agent MVP

The Tuning Agent MVP is a Python-based workflow for identifying repeated security alert noise, drafting narrowly scoped tuning recommendations, and routing those recommendations through human approval before anything is treated as safe.

The goal is not to auto-suppress alerts. The goal is to help analysts and managers see where repeated false-positive or duplicate case volume exists, preserve the evidence behind each recommendation, and create an auditable feedback loop for better detection tuning over time.

## Executive Summary

Security teams often spend time reviewing repeated cases that have already been closed as false positives or duplicates. This project looks for those repeat patterns, groups similar cases together, and proposes tuning candidates that can reduce future noise without hiding meaningful risk.

At a high level, the agent:

- Pulls recent case data from TheHive.
- Finds repeated cases with false-positive or duplicate disposition language.
- Groups cases by stable security context, such as rule ID, host/agent, CVE, file path, or process.
- Classifies the alert type into a bucket such as vulnerability, IOC, authentication, endpoint process, cloud, network, email, or privilege activity.
- Builds a human-readable recommendation with proposed tuning logic, expected impact, risk, validation steps, and safety notes.
- Posts the recommendation to Discord for analyst review.
- Records analyst decisions back into local state and knowledge-base files.
- Optionally sends approved recommendations to a Google Apps Script webhook for tracking in a sheet or external approval record.

## Current Status

This is an MVP intended for review, demonstration, and controlled analyst workflow testing. It is designed around human-in-the-loop approval and local knowledge-base learning.

The current implementation supports:

- TheHive case retrieval.
- Discord recommendation delivery.
- Discord approval command handling.
- Optional local Ollama/Qwen recommendation generation.
- Conservative fallback behavior when LLM generation is disabled or unavailable.
- Local Markdown knowledge-base updates for approved, rejected, stale, and drifted tuning examples.
- Local recommendation state tracking to avoid repeatedly sending the same cluster.

## Workflow

1. `tuning_agent.py` queries TheHive for recent cases.
2. Cases are filtered for false-positive or duplicate indicators.
3. Matching cases are grouped into clusters using `rule_id`, `agent`, and the most specific available indicator.
4. Each cluster is classified by `alert_bucket.py`.
5. Relevant local knowledge-base context is retrieved by `knowledge_retriever.py`.
6. A recommendation is generated.
7. Safety validation checks prevent broad or unsafe recommendations from being treated as approval-ready.
8. The recommendation is posted to Discord.
9. An analyst responds in Discord with `APPROVE`, `REJECT`, `REVIEW`, `STALE`, or `DRIFT`.
10. `approval_bot.py` updates local state and appends the feedback to the correct knowledge-base file.

## Human Approval Model

The agent is intentionally advisory. It does not directly deploy tuning changes.

Analysts review each recommendation and respond with one of the following commands:

```text
APPROVE TR-ID-HERE why this is safe
REJECT TR-ID-HERE why this is unsafe
REVIEW TR-ID-HERE what needs more validation
DRIFT TR-ID-HERE what changed from the previous tuning context
STALE TR-ID-HERE why the previous tuning context is no longer valid
```

Approved recommendations are recorded as positive examples. Rejected recommendations become negative examples. Stale or drifted recommendations are recorded separately so the agent can avoid blindly reusing old approval context when the environment changes.

## AI Usage Boundary

AI is only used during recommendation drafting, and only when local Ollama/Qwen generation is enabled with `USE_QWEN=true`.

The agent does not use AI to:

- Decide which cases to pull from TheHive.
- Query or modify TheHive.
- Decide which cases qualify as false positives or duplicates.
- Build cluster keys.
- Classify alert buckets.
- Approve recommendations.
- Deploy tuning changes.

Those steps are handled by deterministic Python logic, keyword matching, local configuration, and human analyst decisions.

When enabled, Qwen receives the already-selected case cluster and local knowledge-base context, then drafts recommendation fields such as:

- Why the cases appear related.
- Suggested tuning.
- Proposed logic.
- Expected impact.
- Risk assessment.
- Validation steps.
- Safety notes.

The drafted output is still checked by deterministic safety validation. If the draft appears too broad or misses required context, the recommendation is downgraded to `REVIEW`.

## Safety Guardrails

The MVP uses several guardrails to keep recommendations narrow:

- Recommendations are grouped around stable fields such as rule ID, host/agent, CVE, file path, process, or other indicators.
- The prompt explicitly rejects broad tuning patterns such as global rule suppression.
- Proposed logic must reference the rule ID.
- Proposed logic must reference the host/agent when one is available.
- Proposed logic must reference the correlation indicator when one is available.
- The safety validator downgrades risky recommendations to `REVIEW`.
- Analyst approval is required before a recommendation is considered accepted.
- Knowledge-base feedback is separated by approval lane so rejected patterns do not become positive examples.

Examples of intentionally unsafe patterns:

- Suppressing an entire detection rule globally.
- Suppressing all alerts from a host.
- Suppressing all PowerShell activity.
- Suppressing all vulnerability detections.
- Tuning IOC alerts without confirmed benign or allowlisted context.
- Hiding privilege changes without a known approved admin workflow.

## Alert Buckets

`alert_bucket.py` classifies clusters into broad alert families. Each family has a preferred grouping strategy and a tuning goal.

| Bucket | Purpose |
| --- | --- |
| `vulnerability` | Reduce duplicate vulnerability case creation while preserving vulnerability visibility. |
| `ioc` | Avoid suppressing malicious indicators unless they are confirmed benign or allowlisted. |
| `endpoint_process` | Tune exact known-benign process behavior while preserving suspicious variants. |
| `authentication` | Reduce known benign authentication noise while preserving visibility for new users, privileged users, and new sources. |
| `identity_privilege` | Preserve visibility for privilege changes and tune only approved recurring admin workflows. |
| `cloud` | Reduce expected cloud service or admin activity while preserving unusual principals, regions, and sensitive actions. |
| `network` | Tune known benign network patterns while preserving new destinations and suspicious ports or protocols. |
| `email` | Avoid broad phishing suppression and tune only known benign sender or campaign patterns. |
| `generic` | Use conservative review-first handling when the alert type is unclear. |

## Repository Structure

| Path | Description |
| --- | --- |
| `tuning_agent.py` | Main recommendation generator. Pulls TheHive cases, groups clusters, builds recommendations, and posts to Discord. |
| `approval_bot.py` | Discord bot that handles analyst decisions and updates local state and knowledge-base files. |
| `approve_tuning.py` | Command-line helper for approving a specific recommendation ID. |
| `alert_bucket.py` | Alert-family classifier and bucket metadata. |
| `feedback_interpreter.py` | Converts analyst decisions into structured behavior-change metadata. |
| `knowledge_retriever.py` | Simple keyword retrieval over local Markdown knowledge documents. |
| `knowledge_base/` | Local tuning examples, SOC tuning guidance, MITRE notes, and feedback history. |
| `seed_*.py` | Test/demo scripts for creating sample cases. |
| `.env.example` | Safe configuration template. Real secrets belong in `.env`, which is ignored by Git. |
| `requirements.txt` | Python dependencies. |

## Knowledge Base

The local knowledge base gives the agent memory without requiring an external vector database.

Important files include:

- `knowledge_base/approved_tuning_examples.md`
- `knowledge_base/rejected_tuning_examples.md`
- `knowledge_base/stale_tuning_examples.md`
- `knowledge_base/feedback_change_log.md`
- `knowledge_base/tuning_ideology.md`
- `knowledge_base/soc_tuning_skillset.md`
- `knowledge_base/mitre_attack_notes.md`

Retrieval is currently keyword-based. `knowledge_retriever.py` scores Markdown documents by query-term overlap and returns the top matching documents. This is simple by design for the MVP and can later be upgraded to embeddings or a vector store.

## Configuration

Create a local `.env` from the template:

```bash
cp .env.example .env
```

Expected settings:

| Variable | Description |
| --- | --- |
| `THEHIVE_URL` | Base URL for TheHive. |
| `THEHIVE_API_KEY` | API key used to query TheHive cases. |
| `DISCORD_WEBHOOK_URL` | Discord webhook used by `tuning_agent.py` to post recommendations. |
| `DISCORD_BOT_TOKEN` | Discord bot token used by `approval_bot.py`. |
| `APPROVAL_CHANNEL_ID` | Discord channel ID where approval commands are accepted. |
| `APPS_SCRIPT_WEBHOOK_URL` | Optional Google Apps Script webhook for approved recommendation tracking. |
| `APPS_SCRIPT_SECRET` | Shared secret for the Apps Script webhook. |
| `APPROVER` | Default approver name for command-line approval workflows. |
| `OLLAMA_URL` | Optional local Ollama endpoint. |
| `OLLAMA_MODEL` | Optional model name, defaulting to `qwen2.5:7b`. |
| `USE_QWEN` | Set to `true` to enable local LLM recommendation generation. |
| `LOOKBACK_DAYS` | Number of days described in the recommendation summary. |
| `MIN_OCCURRENCES` | Minimum cluster size before a recommendation is sent. |

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create local configuration:

```bash
cp .env.example .env
```

Then fill in `.env` with the appropriate local values.

## Contributor Ollama Setup

Contributors can run the recommendation-generation path with a local Ollama model. This keeps LLM testing local and avoids sending case context to an external model provider.

Install Ollama from:

```text
https://ollama.com
```

Pull the default model used by this project:

```bash
ollama pull qwen2.5:7b
```

Start Ollama:

```bash
ollama serve
```

Configure `.env`:

```bash
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
USE_QWEN=true
```

If contributors do not want to use Ollama, leave Qwen disabled:

```bash
USE_QWEN=false
```

When `USE_QWEN=false`, or when Ollama is unavailable, the agent falls back to a conservative review-required recommendation instead of failing open.

## Running the Agent

Generate and send tuning recommendations:

```bash
python tuning_agent.py
```

Run the Discord approval bot:

```bash
python approval_bot.py
```

Approve a recommendation from the command line:

```bash
python approve_tuning.py TR-ID-HERE "approval notes"
```

## Recommendation Output

Each Discord recommendation includes:

- Recommendation ID.
- Alert bucket.
- Detection source and rule ID.
- Case count and example case IDs.
- Correlation criteria.
- Explanation of why the cases appear related.
- Suggested tuning.
- Proposed Wazuh-style logic.
- Expected impact.
- Risk assessment.
- Validation steps.
- LLM recommended decision.
- Safety notes.
- Human approval instructions.

## Data Handling

This repository intentionally excludes secrets, runtime state, local virtual environments, and generated backup files.

Ignored files include:

- `.env`
- `venv/`
- `__pycache__/`
- `sent_recommendations.json`
- `*.bak.*`

The committed `.env.example` file contains placeholders only.

## Manager Review Notes

This MVP is useful for evaluating:

- Whether repeated SOC case volume can be translated into reviewable tuning opportunities.
- Whether recommendations include enough evidence for a manager or lead analyst to assess value and risk.
- Whether the human approval loop is clear enough for operational use.
- Whether positive and negative feedback can become reusable tuning guidance.
- Whether alert-noise reduction can be pursued without weakening detection coverage.

The most important design decision is that approval stays with humans. The agent helps prepare the evidence, propose narrow logic, and document feedback, but it does not make final production tuning decisions by itself.

## Future Improvements

Potential next steps:

- Add tests around clustering, bucket classification, and feedback parsing.
- Add richer case enrichment in `case_enrichment.py`.
- Replace keyword retrieval with embeddings or a vector database.
- Add structured JSON schema validation for generated recommendations.
- Add a dashboard or report view for recommendation history.
- Add CI checks for formatting, linting, and secret scanning.
- Add integration tests with mocked TheHive, Discord, and Apps Script endpoints.
- Add support for exporting approval records to a formal change-management system.
