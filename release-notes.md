## v0.2.1

A packaging fix release. The `parzival` and `parzival-broker` binaries behave exactly as in
v0.2.0. Parzival is still **pre-1.0**.

### Fixed: package upgrades no longer disable a running broker

The RPM and DEB packages' remove script ran `systemctl disable --now` on
`parzival-broker.service` and `check-parzival-broker.timer` unconditionally. Both rpm and
dpkg also run the old package's remove script during an upgrade. So every package upgrade
stopped and disabled a running, enabled broker and its health-check timer, and nothing
started them again.

From this release:

- The remove script stops and disables the units only on a real removal (`dnf remove`,
  `apt remove`). An upgrade leaves them enabled or disabled as it found them.
- On an upgrade, a broker that is already running is restarted (`systemctl try-restart`),
  so the new `parzival-broker` binary is the one serving. A stopped broker stays stopped,
  and the package still never enables or starts a unit on its own.
- CI now runs the package scripts under every argument rpm and dpkg pass them, and checks
  that the built packages embed the scripts unchanged.

### Upgrading from v0.2.0 or earlier — read this first

The fix cannot protect the upgrade **from** v0.2.0 or earlier. The package being replaced
runs its own, unguarded copy of the remove script, so this one upgrade still disables the
broker unless you prevent it. If the broker is enabled on the host:

```bash
systemctl is-enabled parzival-broker.service check-parzival-broker.timer   # note the state

# RPM: skip the old package's remove script
sudo dnf download parzival
sudo rpm -Uvh --nopreun parzival-0.2.1-1.*.rpm

# DEB: upgrade, then re-enable what was enabled
sudo apt install parzival
sudo systemctl enable --now parzival-broker.service check-parzival-broker.timer
```

Hosts that never enabled the broker can upgrade normally. Every later upgrade, from v0.2.1
onward, needs none of this. See INSTALL.md, "Upgrading an RPM or DEB install".

See [README.md](README.md), [INSTALL.md](INSTALL.md), [MANUAL.md](MANUAL.md), and
[THREAT-MODEL.md](THREAT-MODEL.md) for the full design, installation, usage, and security
model.
