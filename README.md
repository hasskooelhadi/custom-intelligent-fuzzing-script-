# common – intelligent ffuf wrapper

`common` is a small helper around [ffuf](https://github.com/ffuf/ffuf) that keeps
only the unique responses you care about.  It automatically groups matches by
status code, word count, line count, content length and response body so that
repetitive noise (for example boilerplate 404 pages) is hidden while unique
behaviour is highlighted immediately.

## Features

- Runs `ffuf` with your preferred arguments while streaming JSON output in real
  time.
- Stores raw responses to disk (using ffuf's `-od` support), hashes the
  contents and collapses identical results.
- Prioritises filtering of duplicate 404 pages but warns you whenever other
  status codes repeat so you can still review at least one of them manually.
- Detects when different responses share the same size/word/line metrics so you
  can double check for subtle variations.
- Accepts piped input from other tools, falls back to the standard
  `/usr/share/seclists/Discovery/Web-Content/common.txt` wordlist when needed.
- Supports every ffuf CLI flag – pass them after the required arguments and
  they are forwarded to ffuf untouched.

## Usage

```bash
common <url> <threads> <filter_words> [ffuf options]
```

Example:

```bash
# First pass – explore the target quickly
common http://target.tld/FUZZ 100 2123 -H "User-Agent: fuzz" -mc 200

# Pipe a custom wordlist directly from another tool
cat endpoints.txt | common https://api.target.tld/FUZZ 50 34 -H "Authorization: Bearer <token>"
```

### Options provided by `common`

| Flag | Description |
| ---- | ----------- |
| `-W`, `--default-wordlist` | Override the fallback wordlist used when `-w` is not supplied and no data is piped on stdin. |
| `--ffuf-binary` | Path to the `ffuf` executable (defaults to `ffuf` in your `PATH`). |
| `--show-duplicates` | Log filtered duplicates as they are detected. |
| `--keep-temp` | Preserve the temporary ffuf output directory and any wordlist generated from stdin. |

All other options are passed straight to `ffuf`.  Auto-calibration (`-ac`) is
ignored intentionally so that the custom deduplication strategy can take full
control of the filtering.

## Output

For every unique response the tool prints a detailed summary including the
request that triggered it, key metrics (status, length, words, lines) and where
its body was stored.  Duplicates are suppressed, but at the end you receive a
concise summary that lists:

- how many responses were processed vs. kept,
- how many duplicate 404s were filtered automatically,
- non-404 responses that repeated and therefore deserve a manual check,
- size/word collisions where multiple distinct responses shared the same
  metrics (handy for spotting tricky edge cases).

If you need to review every raw response, run with `--keep-temp` to prevent the
temporary directory from being removed.

## Notes

- The wrapper requires ffuf >= 1.5 with JSON streaming support.
- Because ffuf is invoked with `-json`, progress information is written to
  stderr and remains visible while unique hits are printed to stdout.
- When piping input, remember to include a trailing newline so the temporary
  wordlist contains all entries.
