# Contributing

## Branches

Each supported GLPI major version has its own line of plugin releases and its own branches.

| GLPI   | Plugin versions | Release branch | Development branch |
|--------|-----------------|----------------|--------------------|
| 12.x   | 0.2.x           | `main`         | `dev12`            |
| 11.x   | 0.1.x           | `glpi11`       | `dev11`            |
| 10.x   | 0.0.x           | `0.0.x` (no longer maintained) | -  |

- Work for a GLPI version is done on its development branch and merged into its release branch.
- `main` always follows the newest supported GLPI version.
- The two lines cannot share code as is: GLPI 12 types the properties of its base classes
  (`CommonDBTM::$dohistory`, `$rightname`, ...), so a class valid for GLPI 12 does not load on GLPI 11 and vice versa.

## GLPI compatibility

The supported GLPI range is declared in two places, which must agree on each branch:

- `setup.php`: `PLUGIN_WAZUH_MIN_GLPI_VERSION` (inclusive) and `PLUGIN_WAZUH_MAX_GLPI_VERSION` (exclusive),
- `wazuh.xml`: `<compatibility>` of the first `<version>` entry (e.g. `~12.0`).

## Releases

Releases are made by the GitHub Actions workflow `.github/workflows/release-main.yml` ("Auto Release"),
which runs on every push to the release branch of the line (`main` for GLPI 12, `glpi11` for GLPI 11).

To release:

1. On the development branch, bump the version in `wazuh.xml`: the **first** `<version>` entry
   (`<num>` and `<download_url>`). The version must be new: a release whose tag already exists fails.
2. Merge the development branch into the release branch and push it.

The workflow then:

1. compiles the translations (`locales/*.po` to `*.mo`),
2. reads the version from the first `<version>` entry of `wazuh.xml`,
3. builds `wazuh-<version>.tar.gz` (the repository without `.git` and `.github`),
4. creates the tag `<version>` and a GitHub release with the archive attached.

### `wazuh.xml` and the GLPI plugins catalog

The GLPI plugins catalog reads `wazuh.xml` from the URL registered for the plugin (the `main` branch).
It lists one entry per supported GLPI version
(newest first). After a release from `glpi11`, update the `~11.0` entry in `wazuh.xml` on `main`
(`<num>` and `<download_url>`) so that the catalog offers the new GLPI 11 version.
The first entry on `main` must stay the newest GLPI line, because the `main` workflow releases it.
