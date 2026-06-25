# Tuning Agent

Python tooling for identifying repeated false-positive or duplicate security cases, generating tuning recommendations, and routing analyst approval feedback into a local knowledge base.

## What It Does

- Pulls recent cases from TheHive.
- Groups repeated cases by rule, host/agent, and stable indicators such as CVE, path, or process.
- Builds tuning recommendations with knowledge-base context.
- Sends recommendations to Discord for review.
- Records approved, rejected, stale, and review feedback for future recommendations.
- Optionally forwards approved recommendations to a Google Apps Script webhook.

## Main Files

- `tuning_agent.py` - fetches cases, builds clusters, generates recommendations, and posts to Discord.
- `approval_bot.py` - listens for Discord approval decisions and updates recommendation state and knowledge-base notes.
- `approve_tuning.py` - command-line approval helper for a specific recommendation ID.
- `alert_bucket.py` - classifies recommendation buckets.
- `feedback_interpreter.py` - converts analyst decisions into structured feedback metadata.
- `knowledge_retriever.py` - retrieves relevant local knowledge-base notes.
- `knowledge_base/` - local examples, ideology, MITRE notes, and analyst feedback history.
- `seed_*.py` - test/demo case seed scripts.

## Setup

1. Create a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create local configuration:

   ```bash
   cp .env.example .env
   ```

4. Fill in `.env` with the local TheHive, Discord, Google Apps Script, and optional Ollama settings.

## Running

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

## Notes for Reviewers

Secrets and local state are intentionally excluded from GitHub:

- `.env`
- `venv/`
- `__pycache__/`
- `sent_recommendations.json`
- backup files such as `*.bak.*`

Use `.env.example` as the configuration template.

