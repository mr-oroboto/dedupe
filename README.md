# dedupe

A small tool to find duplicate files within a directory structure and
optionally remove them.

## Usage

```
$ dedupe [-r] [-v] <directoryToScan>

  -r	remove all duplicates (leaving one original copy)
  -v	verbose (explain what is being done)
```

Running without the `-r` option is essentially a dry run that reports dupes and
the space they occupy but will not remove them.
