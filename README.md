# pkcs11-mldsa


# Small sample app to test out mldsa in softHSM

# Will build a docker image, with openssl 3.5.1 and then build the forked version of SoftHSM by antoinelochet

# Also includes a small golang app to generate an MLDSA Key Pair

## Git hooks

Enable the repo-local hooks so the pre-commit runs:

```
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

What it does:
- Truncates tracked files matching *.log
- Truncates files under log/ and logs/
- Re-adds them to the commit so they remain empty