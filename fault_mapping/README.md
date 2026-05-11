# EvoMaster to OWASP database, with mitigation scaffolding

This pipeline turns EvoMaster's generated Java test files into rows in the
`OWASP_TOP_10_API_VULNERABILITIES` database, and scaffolds matching
directories in the mitigations Git repository.

## Components

1. `import_evomaster.py`, the local importer. Parses EvoMaster's generated
   `*_Test.java` files, writes to MySQL, and emits a manifest.
2. `manifests/repo_paths.json`, the manifest. Committed to the mitigations
   repo, read by the Action.
3. `.github/workflows/create-mitigation-dirs.yml`, the nightly Action. Reads
   the manifest, creates any missing directories with `.gitkeep` placeholders,
   commits the changes.

## End to end flow

```
EvoMaster generated .java files (e.g. *_faults_Test.java)
        |
        v
import_evomaster.py  ----->  MySQL (mitigations table)
        |
        v
manifests/repo_paths.json   (you commit this manually)
        |
        v
nightly GitHub Action
        |
        v
new directories with .gitkeep files
```

## Running the importer

```bash
pip install mysql-connector-python
python3 import_evomaster.py path/to/em-tests-dir/
```

The argument can be a directory containing `.java` files (recursively scanned)
or a single `.java` file. By default the manifest is written to
`manifests/repo_paths.json`, override with `--manifest some/other/path.json`.

Edit `DB_CONFIG` at the top of the script for your MySQL credentials, or
leave the password empty to be prompted at runtime.

## What gets parsed

For each `@Test` method in the Java files, the parser extracts:

The fault codes declared in the docstring's `Type-codes: 100, 101` line, the
HTTP method and path from the `Calls:` section (using the last call in
multi-step tests, since that is the one that triggers the fault), and the
inline `// Fault100. <detail>` comments inside the method body, which carry
the precise reason (stack trace location, schema validation error, etc.).

## Path format

`repo_path` is generated deterministically from the OWASP category, the
subcategory, and the vulnerability name. For example:

```
api8_security_misconfiguration/server_error_handling/unhandled_internal_crash/search_replace.json
```

The slug function lowercases everything, replaces non alphanumeric runs with
underscores, and trims leading/trailing underscores. Anything stored under
that path in the repo is the actual mitigation content, the row in the DB
only points at it.

## When a path is manually overridden

If a `mitigations` row already has a non-default `repo_path` (anything other
than `TBD` or the computed default), the importer leaves it alone and the
manifest reflects the existing value. This means manual curation survives
re-imports.

## Idempotency

The Action only creates directories that don't already exist. It never
deletes, never overwrites, never touches `.gitkeep` files that someone has
replaced with real content. Safe to run on a schedule indefinitely.

## Required subcategories

The importer looks up `subcategory_name` against the `subcategories` table at
runtime. If a name is missing, the fault is skipped with a clear error. Add
the subcategory to the DB first (or update `FAULT_MAPPING` to point at an
existing name) and re-run.
