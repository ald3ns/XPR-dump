# XPR-dump

This repo contains all the supporting material for this blog post: https://alden.io/posts/secrets-of-xprotect/.

Keep in mind that if you don't have a commercial Binary Ninja license, you won't be able to run the extractor headlessly. You can still run it from within the app via `File > Run Script...`.

## Repo Structure

Files

- `setup.sh`: a helper script to copy the remediators and perform extraction
- `xpr-dump.py`: a binaryninja script to dump the strings from an XPR

Folders

- `/rules`: all the cleaned YARA rules
- `/output`: the raw output from string decryption
- `/notes`: a collection of notes about a subset of the YARA rules
