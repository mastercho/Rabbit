# Changelog

Versions use `vMAJOR.MINOR.PATCH` tags. Each tag has a GitHub Release. Historical baselines stay on the GitHub `main` commit from that time. Those commits are not rewritten.

## v0.3.1 - 2026-09-30

- Restored the report service, vulnerability report API, frontend UI, and matching tests to the v0.2.1 baseline, as requested. Removed the delivery-draft module added in v0.3.0.
- Kept the Docker frontend build, the private worker config mount, and the secret-exclusion rules so a rollback does not drop page assets or leak keys.
- Decide, Execute, and conclude were not changed in this release.

## v0.3.0 - 2026-09-30

### Changes

- Vulnerability delivery preview and Markdown, PDF, and DOCX export share one read-only delivery payload and call out evidence gaps. Client formats export confirmed vulnerabilities by default so empty reports are avoided.
- The backend only syncs the Finding projection. Report preview and export do not call a model and do not write Findings back. Discovery still belongs to Decide, Execute, and conclude.
- The workspace can switch between the fact graph and a list, and falls back when the graph is unavailable. Project and vulnerability filters, the worker list, and detail interactions were tightened.
- The default template uses 8 GLM-5.3 Pi workers with a dispatch cap of 6. Actual model quality depends on your configuration and the model service.
- Frontend assets are built in the Docker image, so a fresh clone no longer misses gitignored static files.
- Updated affected dependencies in the frontend lockfile and cleared the known npm audit alerts at that time.
- Added a gitignored local worker config and install/upgrade notes so model and service keys are not published with the public repository.

### Upgrade note

Save the previous worker config as `dispatch.local.yaml`. Do not commit real keys into `dispatch.yaml`. Back up the database, the evidence volume, and the config before upgrading. See [INSTALL.md](INSTALL.md).

## v0.2.1 - initial public baseline

The baseline is commit `0f2e72b` on `main` of the original public repository. It includes the Cairn-Y single loop, the fact graph, project and worker management, the Finding-driven vulnerability view, and basic report export. This tag marks existing history. It does not rewrite that code.
