# secledger demo — a VHS tape (https://github.com/charmbracelet/vhs)
#
# Regenerate the GIF (run from the repo root):
#     pip install -e .
#     vhs demo/demo.tape      # writes demo/demo.gif
#
# Deterministic by design: explicit --run-id values mean the same tape always
# records the same output, so the GIF never drifts from the tool.

Output demo/demo.gif

Set Shell bash
Set FontSize 15
Set Width 1200
Set Height 780
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

# --- hidden setup: clean slate -------------------------------------------
Hide
Type "cd $(git rev-parse --show-toplevel) && rm -f ledger.json LEDGER.md && clear" Enter
Show
Sleep 500ms

# 1. Convert a ZAP scan to findings and load the ledger
Type "# A DAST (ZAP) scan -> findings -> ledger" Enter
Type "secledger-adapt zap examples/adapters/zap.raw.json --run-id dast-11-18 --target staging | secledger ingest -" Enter
Sleep 2.5s

# 2. Add a Trivy container scan to the SAME ledger
Type "# A different scanner (Trivy) into the same ledger" Enter
Type "secledger-adapt trivy examples/adapters/trivy.raw.json --run-id image-11-18 --target ci | secledger ingest -" Enter
Sleep 2.5s

# 3. Re-run the first scan: idempotent, nothing duplicates
Type "# Re-run yesterday's scan -> 0 new (idempotent)" Enter
Type "secledger-adapt zap examples/adapters/zap.raw.json --run-id dast-11-18 --target staging | secledger ingest -" Enter
Sleep 2.5s

# 4. Show the deduped ledger
Type "secledger show" Enter
Sleep 3s

# 5. Preview the issues it would file (dry-run: no token, no writes)
Type "# Preview the GitLab issues it would open" Enter
Type "secledger file --tracker gitlab --url https://gitlab.example --project team/app --min-severity medium --dry-run" Enter
Sleep 4s

# --- hidden teardown ------------------------------------------------------
Hide
Type "rm -f ledger.json LEDGER.md" Enter
