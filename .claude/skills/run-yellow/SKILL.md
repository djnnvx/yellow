---
name: run-yellow
description: Run the yellow recon pipeline against a target. Discovers the binary's actual subcommands and flags at runtime, asks which modules to enable, then runs the chain stage by stage. Use when asked to run yellow, kick off recon, or scan a target with this tool.
allowed-tools: Bash(yellow*), Bash(./yellow*), Bash(command -v *), Bash(test *), Bash(ls *), Bash(cat *), Bash(wc *), Bash(head *), Bash(find *), Bash(git rev-parse*), AskUserQuestion, Read
---

You run the `yellow` recon pipeline one stage at a time, so the user sees output
and can stop between stages.

**Never hardcode what yellow can do.** Modules and flags change every release.
Discover them from `--help` at runtime and build your questions from what you
actually find. If this file names a flag that no longer exists, `--help` wins.

## 0. Resolve the binary

A stale binary is the single most common way to waste a run. Do this first:

```bash
command -v yellow
git rev-parse --show-toplevel 2>/dev/null
```

If the working directory is inside a yellow checkout, prefer a freshly built
`./yellow` over whatever is on PATH, and say which one you picked. Check for
staleness before trusting either:

```bash
ls -la --time-style=+%Y-%m-%d\ %H:%M "$(command -v yellow)" 2>/dev/null
find . -name '*.go' -newer "$(command -v yellow)" 2>/dev/null | head -3
```

If any source file is newer than the binary, tell the user it is stale and offer
to `make` before running. Do not silently scan with an old build.

If no binary exists anywhere, stop and say so.

## 1. Discover capabilities

```bash
yellow --help
```

Parse the `Available Commands:` block. Ignore cobra's built-ins (`completion`,
`help`). Everything else is a real stage.

Then, for each subcommand you intend to offer:

```bash
yellow <subcommand> --help
```

Read the flags off that output. That is the source of truth for:

- which optional modules exist and whether each is opt-in (`--foo`) or
  on-by-default with an opt-out (`--no-foo`)
- tunables (depth, duration, caps, ports, wordlist, rate limit, proxy)
- whether a dry-run flag exists

Note anything a flag's help text warns about (large downloads, extra requests,
required API keys) and surface it in the question you build from it.

Every invocation prints an ASCII banner first, and it contains a `--------`
run that a naive flag grep will pick up as a flag. Read the `Flags:` block
rather than grepping the whole output for leading dashes.

## 2. Confirm scope

The target is a **bare domain or IP**: no scheme, no trailing path. It is used
both as the loot directory name and the scan target, so anything else breaks the
downstream paths.

If the user gave no target, ask. Then confirm once that it is in scope for an
authorized engagement, because the osint and scan stages touch it directly. One
confirmation up front is enough; do not re-ask per stage.

The loot tree is created in the current working directory. If that is a git
repo, say so and offer to run somewhere else rather than dropping a loot tree
into their source.

## 3. Ask what to run

Use `AskUserQuestion`, with options built from what step 1 actually found. Do
not offer a module that is not in the help output. Typical shape:

- **Stages**: which of the discovered subcommands to run, and in what order.
  The usual chain is tree, then osint, then prune, then scan, because each
  consumes the previous one's output.
- **Optional scan modules**: one multi-select built from the opt-in flags you
  discovered. Put the cost in each description (slow, loud, downloads N MB,
  needs a wordlist, extra request per URL).
- **Default-on modules**: if you found `--no-*` flags, ask whether to disable
  any. Mention what is lost, since these are usually on for a reason.
- **Tunables**: only ask when the default is likely wrong for this target, for
  example a crawl budget on a large site.

Skip the questions entirely if the user already said exactly what they want
("just osint", "no port scan", "full chain, nuclei on"). Honour that directly.

## 4. Run the chain

Run stages in order. Stop if one fails. Between stages, verify the next stage's
input actually exists and is non-empty:

```bash
wc -l <the file the next stage reads>
```

If an input is missing or empty, stop and say so rather than running a stage
that cannot work. This matters most when the user asked for a subset: prune
needs a domain list from a prior osint run, and scan needs prune's output.

**Long stages go in the background.** osint and scan take minutes. Launch them
with Bash `run_in_background: true` so the session stays responsive, and wait
for the completion notification instead of polling.

Do not pipe a backgrounded stage through `tail`, `head` or `grep`. Those buffer,
so you get nothing until the process exits and you lose all progress visibility.
Write the raw output and filter it when you read it.

Where output lands depends on the `-d` you pass, and stages differ in whether
they expect the loot root or a subdirectory. Check the actual paths on disk
after the first stage rather than assuming, then feed those exact paths onward.

## 5. Report

Point the user at the real artifacts. List what was written rather than
describing it from memory:

```bash
find <loot dir> -type f -newer <marker> | head -40
```

Report honestly. Zero findings is a valid result and should be stated plainly.
If a module self-skipped for a missing API key, say which and why. If a stage
was capped or truncated, say what was dropped.

Several outputs contain live credentials or client data. Treat the loot tree
accordingly and never paste secret values into a summary that might be shared.
