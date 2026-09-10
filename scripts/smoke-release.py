#!/usr/bin/env python3
"""Exercise an installed release binary with temporary TLS and database files."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import socket


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--runner", default="")
    args = parser.parse_args()
    prefix = shlex.split(args.runner) + [str(args.binary.resolve())]
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="easy-sshca-release-") as directory:
        root = Path(directory)
        process = None
        log = (root / "server.log").open("w")

        def cli(config, *command, secret=None):
            output = subprocess.run(
                prefix + ["--json", "--config", str(config)] + list(command),
                input=secret, text=True, capture_output=True, timeout=30,
            )
            if output.returncode:
                raise RuntimeError(f"command {command[0]} failed: {output.stderr} {output.stdout}")
            return json.loads(output.stdout)["result"]

        def start():
            return subprocess.Popen(
                prefix + ["server", "start", "--config", str(root / "server.yaml")],
                stdout=subprocess.DEVNULL, stderr=log,
            )

        def stop():
            process.terminate()
            process.wait(timeout=15)

        try:
            cli(root / "unused.yaml", "server", "init", "--name", "Release smoke", "--folder", str(root / "instance"))
            root = root / "instance" / "server"
            rpc_port, https_port = free_port(), free_port()
            endpoint = f"https://localhost:{rpc_port}"
            (root / "server.yaml").write_text(
                f"version: 1\ndatabase: {root}/ca.db\nrpc_listen: 127.0.0.1:{rpc_port}\n"
                f"https_listen: 127.0.0.1:{https_port}\ntls:\n"
                f"  certificate: {root}/tls.crt\n  private_key: {root}/tls.key\n"
                "limits:\n  request_bytes: 65536\n  rpc_timeout: 10s\n  database_queue: 16\n"
            )
            admin_config = root / "operator.yaml"
            cli(admin_config, "configure", "--server", endpoint, "--tls-ca", str(root / "tls.crt"),
                "--api-key-stdin", secret=(root.parent / "admin" / "ca.admin-key").read_text())
            process = start()
            for attempt in range(60):
                try:
                    assert cli(admin_config, "server", "status")["state"] == "LOCKED"
                    break
                except RuntimeError:
                    if process.poll() is not None or attempt == 59:
                        raise
                    time.sleep(0.1)
            cli(admin_config, "server", "unlock", "--secret-stdin", secret=(root.parent / "admin" / "ca.bootstrap-secret").read_text())
            cli(admin_config, "admin", "zone", "add", "production", "--max-duration", "1h")
            cli(admin_config, "admin", "user", "add", "alice", "--max-duration", "1h")
            cli(admin_config, "admin", "user", "grant-zone", "alice", "production")
            token = cli(admin_config, "admin", "access-token", "add", "--user", "alice", "--name", "release", "--max-duration", "30m")
            user_config = root / "user.yaml"
            cli(user_config, "configure", "--server", endpoint, "--tls-ca", str(root / "tls.crt"),
                "--api-key-stdin", "--zone", "production", secret=token["api_key"])
            cli(user_config, "gen-key", "--file", str(root / "id_ed25519"))
            signed = cli(user_config, "sign", "--file", str(root / "id_ed25519.pub"), "--duration", "1d")
            assert signed["effective_duration"] == 1800
            subprocess.run(["ssh-keygen", "-Lf", signed["certificate_file"]], check=True, capture_output=True)
            fingerprint = cli(user_config, "pub-key")["fingerprint"]
            fetched = subprocess.run([
                "curl", "--fail", "--silent", "--show-error", "--cacert", str(root / "tls.crt"),
                f"https://localhost:{https_port}/zones/production/ca.pub",
            ], check=True, capture_output=True, text=True)
            assert fetched.stdout.strip() == cli(user_config, "pub-key")["public_key"]
            cli(user_config, "rotate-token")
            cli(user_config, "sign", "--file", str(root / "id_ed25519.pub"), "--force")
            assert cli(user_config, "pub-key")["fingerprint"] == fingerprint
            stop()
            process = start()
            for attempt in range(60):
                try:
                    assert cli(admin_config, "server", "status")["state"] == "LOCKED"
                    break
                except RuntimeError:
                    if process.poll() is not None or attempt == 59:
                        raise
                    time.sleep(0.1)
            cli(admin_config, "server", "unlock", "--secret-stdin", secret=(root.parent / "admin" / "ca.bootstrap-secret").read_text())
            assert cli(user_config, "pub-key")["fingerprint"] == fingerprint
            print("Release smoke passed: init, TLS, unlock, administration, signing, rotation, restart.")
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            log.close()


if __name__ == "__main__":
    main()
