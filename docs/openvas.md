# OpenVAS/GVM Full Profile

OpenVAS runs as an independent service in `docker-compose.full.yml`. The OpenVAS server is not
installed into the Worker image and is not part of the default offline bundle; the Worker only
contains the lightweight GPL `gvm-cli` client invoked as a subprocess.

```sh
docker compose -f docker-compose.yml -f docker-compose.full.yml \
  --profile full --profile dvwa --profile mock up -d
```

On Windows, `start-full.bat` performs the same startup and enables `OPENVAS_ENABLED=true`.
Submit a task with `mode=full` to execute `host_vuln_scan`.

The upstream `immauss/openvas` image starts in single-container mode, where GMP is attached to
`/run/gvmd/gvmd.sock` rather than a TCP listener. `scripts/openvas-entry.sh` starts the image
normally, waits for the socket, and exposes it through a TLS proxy on `openvas:9390`. The Worker
mounts the OpenVAS data volume read-only to verify the generated CA certificate. The client pins
`python-gvm==27.10.1` and `gvm-tools==26.0.7`, which support GMP 22.7.

The Worker checks TCP/GMP availability and feed state in `capabilities.json`. When the service,
credentials or NVT feed are unavailable, `host_vuln_scan` is marked `unavailable` or `skipped`
without blocking ZAP, Nuclei, Nmap, Wapiti or report generation.

`python-gvm` and its `gvm-tools` CLI are GPL-3.0-or-later. They are installed in an isolated
Worker image layer only so the Worker can invoke the `gvm-cli` executable. Scanner application
code does not import `gvm`, copy its source, or link it as a library. The lifecycle
`create_target -> create_task -> start_task -> poll -> get_report -> cleanup` is implemented
with GMP XML sent by that subprocess.

The upstream `immauss/openvas` image can be replaced with `OPENVAS_IMAGE` when an approved internal
mirror is required. AGPL components remain isolated in the OpenVAS service and are not linked into
the scanner application.

The image includes a baseline vulnerability feed dated 2026-07-27. For a fast first start,
`OPENVAS_SKIP_SYNC=true` uses that baseline and allows GMP to become available immediately.
Set it to `false` when a full online feed synchronization is required; that may take tens of
minutes and is subject to upstream rsync availability.

A real full-mode DVWA task (`e96f67ab-d36b-4134-a028-a75b58a05965`) completed with
`host_vuln_scan=done`, 0 errors, and 0 GVM findings. This verifies the full GMP lifecycle;
the zero result only means the target did not match the available host-level checks.
