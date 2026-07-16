<p align="center">
  <a href="https://mrgana.ai/">
    <img src="https://github.com/usemrgana/.github/raw/main/imgs/cover.png" alt="Mrgana Banner" width="100%">
  </a>
</p>

<div align="center">

# Mrgana

### The open-source AI pentesting tool. Autonomous AI hackers that find and fix your app’s vulnerabilities.

<br/>


<a href="https://docs.mrgana.ai"><img src="https://img.shields.io/badge/Docs-docs.mrgana.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://mrgana.ai"><img src="https://img.shields.io/badge/Website-mrgana.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/mrgana-ai)](https://discord.gg/mrgana-ai)

<a href="https://deepwiki.com/usemrgana/mrgana"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/usemrgana/mrgana"><img src="https://img.shields.io/github/stars/usemrgana/mrgana?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/mrgana-agent/"><img src="https://img.shields.io/pypi/v/mrgana-agent?style=flat-square" alt="PyPI Version"></a>


<a href="https://discord.gg/mrgana-ai"><img src="https://github.com/usemrgana/.github/raw/main/imgs/Discord.png" height="40" alt="Join Discord"></a>
<a href="https://x.com/mrgana_ai"><img src="https://github.com/usemrgana/.github/raw/main/imgs/X.png" height="40" alt="Follow on X"></a>


<a href="https://trendshift.io/repositories/15362?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-15362" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/15362/weekly" alt="usemrgana%2Fmrgana | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usemrgana/mrgana | Trendshift" width="250" height="55"/></a>

</div>


> [!TIP]
> **New!** Mrgana integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production - [Get started with no setup required](https://app.mrgana.ai).

---


## Mrgana Overview

Mrgana are autonomous AI penetration testing agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual proofs-of-concept. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

**Key Capabilities:**

- **Full pentesting toolkit** - reconnaissance, exploitation, and validation out of the box
- **Multi-agent orchestration** - teams of AI pentesters that collaborate and scale
- **Real exploit validation** - working PoCs, not false positives like legacy vulnerability scanners
- **Developer‑first CLI** - actionable findings with remediation guidance
- **Auto‑fix & reporting** - generate patches and compliance-ready pentest reports


<br>


<div align="center">
  <a href="https://mrgana.ai">
    <img src=".github/screenshot.png" alt="Mrgana Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>


## Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities in your applications
- **Rapid Penetration Testing** - Get penetration tests done in hours, not weeks, with compliance reports
- **Bug Bounty Automation** - Automate bug bounty research and generate PoCs for faster reporting
- **CI/CD Integration** - Run tests in CI/CD to block vulnerabilities before reaching production

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key from any [supported provider](https://docs.mrgana.ai/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)

### Installation & First Scan

```bash
# Install Mrgana
curl -sSL https://mrgana.ai/install | bash

# Configure your AI provider
export MRGANA_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
mrgana --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `mrgana_runs/<run-name>`

---

## ☁️ Mrgana Platform

Try the Mrgana full-stack penetration testing platform at **[app.mrgana.ai](https://app.mrgana.ai)** - sign up for free, connect your repos and domains, and launch a pentest in minutes.

- **Validated findings with PoCs** - every vulnerability includes a working proof-of-concept exploit and reproduction steps
- **One-click autofix** - AI-generated security patches as ready-to-merge pull requests
- **Continuous pentesting** - always-on vulnerability scanning that keeps pace with your deployments
- **DevSecOps integrations** - GitHub, GitLab, Bitbucket, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** - AI that builds on past findings, adapts to your codebase, and reduces false positives over time

[**Start your first pentest →**](https://app.mrgana.ai)

---

## ✨ Features

### Agentic Pentesting Tools

Mrgana agents come equipped with a comprehensive offensive security toolkit - the same tools used by professional penetration testers and ethical hackers:

- **HTTP Interception Proxy** - Full request/response manipulation and analysis with Caido
- **Browser Exploitation** - Automated browser for testing XSS, CSRF, clickjacking, and auth bypass flows
- **Shell & Command Execution** - Interactive terminal for exploit development and post-exploitation
- **Custom Exploit Runtime** - Python sandbox for writing and validating proof-of-concept exploits
- **Reconnaissance & OSINT** - Automated attack surface mapping, subdomain enumeration, and fingerprinting
- **Static & Dynamic Code Analysis** - SAST + DAST capabilities for comprehensive application security testing
- **Vulnerability Knowledge Base** - Structured findings with CVSS scoring and OWASP classification

### Comprehensive Vulnerability Scanner

Mrgana identifies, validates, and exploits a wide range of security vulnerabilities across the OWASP Top 10 and beyond:

- **Broken Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL injection, NoSQL injection, OS command injection, SSTI
- **Server-Side Vulnerabilities** - SSRF, XXE, insecure deserialization, RCE
- **Client-Side Attacks** - XSS (stored/reflected/DOM), prototype pollution, CSRF
- **Business Logic Flaws** - Race conditions, payment manipulation, workflow bypass
- **Authentication & Session** - JWT attacks, session fixation, credential stuffing vectors
- **Infrastructure & Cloud** - Misconfigurations, exposed services, cloud security issues
- **API Security** - Broken authentication, mass assignment, rate limiting bypass

### Graph of Agents (Multi-Agent Pentesting)

Advanced multi-agent orchestration for comprehensive automated penetration testing:

- **Distributed Pentesting** - Specialized AI agents for recon, exploitation, and post-exploitation
- **Scalable Security Testing** - Parallel execution across multiple targets for fast, comprehensive coverage
- **Dynamic Coordination** - Agents share discoveries, chain vulnerabilities, and collaborate like a red team

---

## Usage Examples

### Basic Usage

```bash
# Scan a local codebase
mrgana --target ./app-directory

# Security review of a GitHub repository
mrgana --target https://github.com/org/repo

# Black-box web application assessment
mrgana --target https://your-app.com
```

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
mrgana --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
mrgana -t https://github.com/org/app -t https://your-app.com

# Targets from a file, one target per non-empty, non-comment line
mrgana --target-list ./targets.txt

# White-box source-aware scan (local repository)
mrgana --target ./app-directory --scan-mode standard

# Focused testing with custom instructions
mrgana --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Provide detailed instructions through file (e.g., rules of engagement, scope, exclusions)
mrgana --target api.your-app.com --instruction-file ./instruction.md

# Force PR diff-scope against a specific base branch
mrgana -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### Headless Mode

Run Mrgana programmatically without interactive UI using the `-n/--non-interactive` flag - perfect for servers and automated jobs. The CLI prints real-time vulnerability findings and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

```bash
mrgana -n --target https://your-app.com
```

### CI/CD (GitHub Actions)

Mrgana can be added to your pipeline to run a security test on pull requests with a lightweight GitHub Actions workflow:

```yaml
name: mrgana-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Mrgana
        run: curl -sSL https://mrgana.ai/install | bash

      - name: Run Mrgana
        env:
          MRGANA_LLM: ${{ secrets.MRGANA_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: mrgana -n -t ./ --scan-mode quick
```

> [!TIP]
> In CI pull request runs, Mrgana automatically scopes quick reviews to changed files.
> If diff-scope cannot resolve, ensure checkout uses full history (`fetch-depth: 0`) or pass
> `--diff-base` explicitly.

### Configuration

```bash
export MRGANA_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
export MRGANA_REASONING_EFFORT="high"  # control thinking effort (default: high, quick scan: medium)
```

> [!NOTE]
> Mrgana automatically saves your configuration to `~/.mrgana/cli-config.json`, so you don't have to re-enter it on every run.

**Recommended models for best results:**

- [OpenAI GPT-5.4](https://openai.com/api/) - `openai/gpt-5.4`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) - `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-3-pro-preview`

See the [LLM Providers documentation](https://docs.mrgana.ai/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

## Enterprise Pentesting

Get the same Mrgana experience with [enterprise-grade](https://mrgana.ai/demo) controls: SSO (SAML/OIDC), custom compliance-ready penetration testing reports (SOC 2, ISO 27001, PCI DSS), dedicated support & SLA, custom deployment options (VPC/self-hosted), BYOK model support, and tailored AI pentesting agents optimized for your environment. [Learn more](https://mrgana.ai/demo).

## Documentation

Full documentation is available at **[docs.mrgana.ai](https://docs.mrgana.ai)** - including detailed guides for usage, CI/CD integrations, skills, and advanced configuration.

## Contributing

We welcome contributions of code, docs, and new skills - check out our [Contributing Guide](https://docs.mrgana.ai/contributing) to get started or open a [pull request](https://github.com/usemrgana/mrgana/pulls)/[issue](https://github.com/usemrgana/mrgana/issues).

## Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/mrgana-ai)**

## Support the Project

**Love Mrgana?** Give us a ⭐ on GitHub!

## Acknowledgements

Mrgana builds on the incredible work of open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual). Huge thanks to their maintainers!


> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using Mrgana ethically and legally.

</div>
