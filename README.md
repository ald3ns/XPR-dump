# XPR-dump

This repo contains all the supporting material for this blog post: https://alden.io/posts/secrets-of-xprotect/

## Repo Structure

Files

- `setup.sh`: a helper script to copy the remediators and perform extraction
- `xpr-dump.py`: a binaryninja script to dump the strings from an XPR

Folders

- `/rules`: all the cleaned YARA rules
- `/output`: the raw output from string decryption
- `/notes`: a collection of notes about a subset of the YARA rules
