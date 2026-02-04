# Agentic HoneyPot — AI Scam Engagement & Intelligence Extractor

[![Buildathon](https://img.shields.io/badge/Buildathon-India%20Impact%20AI%20%202026-blue)]()
[![License](https://img.shields.io/badge/License-Apache--2.0-lightgrey)]()

> **Agentic HoneyPot** — an AI-driven honeypot service that detects scam messages, engages attackers like a human persona, and extracts structured intelligence for evaluation.

---

## Project Structure

```
AIHoney Pot System/
│
├── app/
│   ├── main.py           # FastAPI entrypoint
│   ├── config.py         # env / paths
│   ├── detector.py       # rule + ML detection
│   ├── agent.py          # persona, trust, escalation
│   ├── llm.py            # llama.cpp wrapper (subprocess/dummy)
│   ├── intelligence.py   # regex extractors
│   └── callback.py       # GUVI final result
├── models/               # (LOCAL) model artifacts (not in repo)
├── data/                 # (LOCAL) training/test CSVs (ignored)
├── sessions.json         # (LOCAL) session state (ignored)
├── requirements.txt
├── start.sh              # render start script
└── README.md
```
