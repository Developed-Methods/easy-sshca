# Run with systemd

This example runs easy-sshca as a dedicated user under the system service manager.
`LimitMEMLOCK=infinity` satisfies the server's requirement for an unlimited locked-memory limit.
The program uses `mlockall` to lock current and future memory pages as they become resident.

Follow the [server setup instructions](../README.md#for-server-operators) through copying the database and configuration.
Set `database: /var/lib/easy-sshca/ca.db` in `/etc/easy-sshca/server.yaml`.
Keep `admin.yaml` on your local machine.

Run these commands on the server from the repository root.
Create the service account:

```sh
sudo useradd --system --user-group --home-dir /var/lib/easy-sshca --no-create-home --shell /usr/sbin/nologin easy-sshca
```

Install the executable built with `cargo install --path . --locked`:

```sh
sudo install -m 0755 ~/.cargo/bin/easy-sshca /usr/local/bin/easy-sshca
```

Grant the service account access to the copied files:

```sh
sudo chown easy-sshca:easy-sshca /var/lib/easy-sshca /var/lib/easy-sshca/ca.db /etc/easy-sshca /etc/easy-sshca/server.yaml
sudo chmod 0700 /var/lib/easy-sshca /etc/easy-sshca
sudo chmod 0600 /var/lib/easy-sshca/ca.db /etc/easy-sshca/server.yaml
```

Install and start the unit:

```sh
sudo install -m 0644 example/easy-sshca.service /etc/systemd/system/easy-sshca.service
sudo systemctl daemon-reload
sudo systemctl enable --now easy-sshca.service
sudo systemctl status easy-sshca.service
```

Unlock the server from your local machine:

```sh
easy-sshca --config ./my-ca/admin.yaml server unlock
```

Every restart requires another unlock, including automatic restarts after failures.
The unit permits writes to `/var/lib/easy-sshca`; other persistent paths are read-only.

Inspect startup failures and the configured memory limit on the server:

```sh
sudo journalctl -u easy-sshca.service -b
sudo systemctl show easy-sshca.service -p LimitMEMLOCK -p LimitMEMLOCKSoft
```

Both memory limits should report `infinity`.
If a container or host policy blocks `mlockall`, allow that syscall before starting the service.
