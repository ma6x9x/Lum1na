# AGENTS.md — Lum1na repository guide

This file is a navigation and remote-inspection guide for AI coding agents. It is intentionally documentation-only and does not change the app, build settings, source code, or tests.

## Repository identity

- Repository: `ma6x9x/Lum1na`
- Default branch: `main`
- GitHub URL: https://github.com/ma6x9x/Lum1na
- GitHub REST API base: https://api.github.com/repos/ma6x9x/Lum1na

## Safely inspect the current repository

Always inspect the current branch state before making assumptions. The following unauthenticated GitHub API endpoints are useful for a remote agent:

- Repository metadata and default branch:
  https://api.github.com/repos/ma6x9x/Lum1na
- Current latest commit on `main`:
  https://api.github.com/repos/ma6x9x/Lum1na/commits?sha=main&per_page=1
- Complete file tree for the current `main` tip:
  https://api.github.com/repos/ma6x9x/Lum1na/git/trees/main?recursive=1
- A specific file as text/JSON:
  https://api.github.com/repos/ma6x9x/Lum1na/contents/<path>?ref=main
- Human-readable commit page:
  https://github.com/ma6x9x/Lum1na/commits/main

For reproducibility, first resolve the latest commit SHA from the commits endpoint, then use that SHA instead of `main` when reading files. This prevents a multi-file inspection from mixing revisions if `main` changes during the session.

## Current navigation map

- `App/` — SwiftUI application entry point and main view.
- `Bootstrap/` — bootstrap coordination.
- `Device/` — device capability checks.
- `Exploit/` — exploit-related Objective-C/Swift implementation and bridges.
- `KernelMap/` — kernel map and kernel read/write support.
- `Primitive/` — primitive provider.
- `Resources/` — compatibility helpers.
- `Session/` — session phases and logging.
- `Support/` — support headers/shims.
- `UI/` — reusable SwiftUI views and visual components.
- `Lum1na.xcodeproj/` — Xcode project and shared scheme.
- `Lum1naTests/`, `UITests/` — test targets.
- `model/` — bundled Core ML model resources.
- `docs/` — project documentation and paste/navigation notes.
- `.github/workflows/` — CI and IPA build workflows.

## Remote-agent operating rules

1. Read this file and the root `README.md` before editing.
2. Resolve and record the latest `main` commit SHA before inspecting source files.
3. Prefer GitHub's Contents API or blob URLs for targeted file reads; use the recursive tree endpoint for discovery.
4. Do not infer that a file is current unless its URL includes the resolved commit SHA.
5. Keep documentation-only navigation changes separate from source or project-file changes.
6. Before proposing a change, inspect the relevant file at the pinned SHA and check the recent commit history.

## Latest inspected `main` snapshot

At the time this guide was added, the latest `main` commit was:

- SHA: `7183299c39e3dddcaab504be755f768a4660827f`
- Message: `Refactor FusionChainDelegate protocol methods`
- Commit page: https://github.com/ma6x9x/Lum1na/commit/7183299c39e3dddcaab504be755f768a4660827f

This snapshot is informational only. Agents must query the commits endpoint above for the current value instead of relying on this section.
