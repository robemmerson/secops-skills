# Third-party content

The MIT licence in `LICENSE` covers this project's own code and writing. It does not cover the
third-party content listed here, which stays under its owners' terms.

## Devo documentation

Devo and the names of its products are trademarks of Devo Technology, Inc. This project is not
affiliated with or endorsed by Devo.

| Path | What it is | Source |
|---|---|---|
| `plugins/devo/skills/devo/references/library/*.md` (except `INDEX.md`) | About 580 SecOps detections: names, descriptions and LINQ queries, reproduced verbatim | Devo "Query and alert library", [docs.devo.com](https://docs.devo.com) |
| `plugins/devo/skills/devo/references/library/INDEX.md` | An index of those detections | Compiled from the same library |
| `plugins/devo/skills/devo/references/table-catalogue.md` | Devo table names by technology category and product | Devo's technology-category pages, [docs.devo.com](https://docs.devo.com) |
| `plugins/devo/skills/devo/references/tables.md`, section 8 | Union tables: purpose, source tables and normalised fields | Devo's union table documentation, [docs.devo.com](https://docs.devo.com) |

Copyright in this material belongs to Devo. It is included, with attribution, so the skill can
answer questions about Devo's standard detections and tables. Check Devo's terms before reusing
it. If you represent Devo and want any of it changed or removed, please open an issue.

The other reference files (LINQ syntax and traps, API notes, table guides, playbooks, hints and
specs) are this project's own descriptions of how Devo behaves, written from public
documentation and testing, and are covered by the MIT licence.

This content ships inside the Devo plugin and its Claude Desktop zip, where each library file and
the union-table section name Devo's documentation as their source.

## Python packages

The skills' scripts use only the Python standard library, so no third-party packages ship with
them. Some tests use PyYAML when it is installed; it is not bundled.
