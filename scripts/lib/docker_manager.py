# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Thin wrapper around the Docker CLI via :mod:`subprocess`.

All Docker interaction in the project goes through this single module,
providing:

- Structured error handling via :class:`DockerError`
- Consistent timeout management
- Debug logging of every command
- A single point of change if Docker CLI output formats evolve

We deliberately use the Docker CLI rather than the Docker SDK
(``docker-py``) to avoid adding a heavy dependency.  The CLI is always
available in GitHub Actions runners.

Usage::

    from docker_manager import DockerManager

    docker = DockerManager()
    docker.run_container(
        image="gerrit-extended:3.13.1-ubuntu24",
        name="gerrit-test",
        ports={18080: 8080, 29418: 29418},
    )
    logs = docker.container_logs("gerrit-test", tail=100)
    docker.stop("gerrit-test")
    docker.remove("gerrit-test")
"""

from __future__ import annotations

import logging
import shlex
import subprocess

from errors import DockerError

logger = logging.getLogger(__name__)


class DockerManager:
    """Thin wrapper around the Docker CLI.

    Every public method translates its arguments into a ``docker …``
    command, runs it via :func:`subprocess.run`, and either returns the
    result or raises :class:`DockerError` with full diagnostic context.
    """

    # ------------------------------------------------------------------
    # Low-level command execution
    # ------------------------------------------------------------------

    def run_cmd(
        self,
        args: list[str],
        timeout: int = 60,
        check: bool = True,
        input_data: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run an arbitrary ``docker <args…>`` command.

        Parameters
        ----------
        args:
            Arguments *after* the ``docker`` prefix.  For example,
            ``["ps", "-q"]`` executes ``docker ps -q``.
        timeout:
            Maximum wall-clock seconds before the process is killed.
        check:
            If *True* (the default), raise :class:`DockerError` when the
            process exits with a non-zero return code.
        input_data:
            Optional string piped to the process's standard input.

        Returns
        -------
        subprocess.CompletedProcess[str]
            The completed process with ``stdout`` and ``stderr`` as
            decoded strings.

        Raises
        ------
        DockerError
            If *check* is True and the process exited with a non-zero
            return code.
        DockerError
            If the process did not complete within *timeout* seconds.
        """
        cmd = ["docker", *args]
        logger.debug("Running: %s", shlex.join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data,
            )
        except subprocess.TimeoutExpired as exc:
            raise DockerError(
                f"docker {args[0]} timed out after {timeout}s",
                returncode=-1,
                stderr=str(exc),
            ) from exc
        except FileNotFoundError as exc:
            raise DockerError(
                "docker executable not found – is Docker installed?",
                returncode=-1,
                stderr=str(exc),
            ) from exc

        if check and result.returncode != 0:
            raise DockerError(
                f"docker {args[0]} failed (exit {result.returncode}): "
                f"{result.stderr.strip()}",
                returncode=result.returncode,
                stderr=result.stderr,
            )

        logger.debug(
            "docker %s exited %d (stdout=%d bytes, stderr=%d bytes)",
            args[0],
            result.returncode,
            len(result.stdout),
            len(result.stderr),
        )
        return result

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def image_exists(self, image: str) -> bool:
        """Return *True* if *image* exists locally."""
        result = self.run_cmd(
            ["image", "inspect", image],
            check=False,
            timeout=30,
        )
        return result.returncode == 0

    def build_image(
        self,
        tag: str,
        dockerfile_dir: str,
        *,
        dockerfile: str = "Dockerfile",
        build_args: dict[str, str] | None = None,
        timeout: int = 300,
    ) -> None:
        """Build a Docker image.

        Parameters
        ----------
        tag:
            The ``-t`` tag for the built image.
        dockerfile_dir:
            Build context directory (also used as the default location
            for the Dockerfile).
        dockerfile:
            Relative path to the Dockerfile within *dockerfile_dir*.
        build_args:
            Optional ``--build-arg`` key-value pairs.
        timeout:
            Maximum seconds for the build.
        """
        args = [
            "build",
            "-t",
            tag,
            "-f",
            f"{dockerfile_dir}/{dockerfile}",
        ]
        for key, value in (build_args or {}).items():
            args.extend(["--build-arg", f"{key}={value}"])
        args.append(dockerfile_dir)

        logger.info("Building image %s …", tag)
        self.run_cmd(args, timeout=timeout)
        logger.info("Image %s built successfully ✅", tag)

    def pull_image(self, image: str, timeout: int = 300) -> None:
        """Pull an image from a registry."""
        logger.info("Pulling image %s …", image)
        self.run_cmd(["pull", image], timeout=timeout)

    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    def run_container(
        self,
        image: str,
        name: str,
        *,
        ports: dict[int, int] | None = None,
        volumes: dict[str, str] | None = None,
        env: dict[str, str] | None = None,
        cidfile: str | None = None,
        detach: bool = True,
        remove: bool = False,
        extra_args: list[str] | None = None,
        command: str | list[str] | None = None,
        timeout: int = 60,
    ) -> str:
        """Start a container and return its ID.

        Parameters
        ----------
        image:
            Docker image to run.
        name:
            Container name (``--name``).
        ports:
            Host→container port mappings (``-p host:container``).
        volumes:
            Host-path→container-path volume mounts (``-v host:container``).
            Append ``:ro`` to the host path for read-only mounts.
        env:
            Environment variables (``-e KEY=VALUE``).
        cidfile:
            If given, write the container ID to this file.
        detach:
            Run in detached mode (``-d``).  Default *True*.
        remove:
            Automatically remove the container when it stops (``--rm``).
        extra_args:
            Additional raw arguments inserted before the image name.
        command:
            Optional command (and arguments) to pass to the container
            entrypoint.
        timeout:
            Maximum seconds to wait for the ``docker run`` command.

        Returns
        -------
        str
            The full container ID (from stdout when detached).
        """
        args: list[str] = ["run"]
        if detach:
            args.append("-d")
        if remove:
            args.append("--rm")
        args.extend(["--name", name])

        if cidfile:
            args.extend(["--cidfile", cidfile])
        for host_port, container_port in (ports or {}).items():
            args.extend(["-p", f"{host_port}:{container_port}"])
        for host_path, container_path in (volumes or {}).items():
            # Support read-only mounts: if host_path ends with :ro, keep it
            if ":ro" in host_path:
                base_path = host_path.replace(":ro", "")
                args.extend(["-v", f"{base_path}:{container_path}:ro"])
            else:
                args.extend(["-v", f"{host_path}:{container_path}"])
        for key, value in (env or {}).items():
            args.extend(["-e", f"{key}={value}"])

        if extra_args:
            args.extend(extra_args)

        args.append(image)

        if command:
            if isinstance(command, str):
                args.append(command)
            else:
                args.extend(command)

        result = self.run_cmd(args, timeout=timeout)
        cid = result.stdout.strip()
        logger.info(
            "Container %s started: %s",
            name,
            cid[:12] if cid else "(no id)",
        )
        return cid

    def stop(self, cid: str, timeout: int = 30) -> None:
        """Stop a running container.

        Sends SIGTERM, waits up to *timeout* seconds, then SIGKILL.
        Silently succeeds if the container is already stopped.
        """
        logger.info("Stopping container %s …", cid[:12])
        self.run_cmd(
            ["stop", "--time", str(timeout), cid],
            check=False,
            timeout=timeout + 10,
        )

    def kill(self, cid: str) -> None:
        """Send SIGKILL to a container."""
        self.run_cmd(["kill", cid], check=False, timeout=15)

    def remove(self, cid: str, force: bool = False) -> None:
        """Remove a container.

        Parameters
        ----------
        cid:
            Container ID or name.
        force:
            If *True*, pass ``-f`` to remove even if running.
        """
        args = ["rm"]
        if force:
            args.append("-f")
        args.append(cid)
        self.run_cmd(args, check=False, timeout=30)
        logger.info("Container %s removed", cid[:12])

    # ------------------------------------------------------------------
    # Container inspection
    # ------------------------------------------------------------------

    def inspect(self, cid: str, format_str: str = "") -> str:
        """Run ``docker inspect`` and return the (formatted) output.

        Parameters
        ----------
        cid:
            Container ID or name.
        format_str:
            Go-template format string (e.g. ``"{{.State.Status}}"``).

        Returns
        -------
        str
            Trimmed stdout of the inspect command.

        Raises
        ------
        DockerError
            If the container does not exist.
        """
        args = ["inspect"]
        if format_str:
            args.extend(["-f", format_str])
        args.append(cid)
        result = self.run_cmd(args, timeout=15)
        return result.stdout.strip()

    def container_state(self, cid: str) -> str:
        """Return the container state (e.g. ``"running"``, ``"exited"``)."""
        return self.inspect(cid, "{{.State.Status}}")

    def container_ip(self, cid: str) -> str:
        """Return the first IP address of a container."""
        return self.inspect(
            cid, "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
        )

    def container_exists(self, cid: str) -> bool:
        """Return *True* if the container exists (regardless of state)."""
        result = self.run_cmd(["inspect", cid], check=False, timeout=15)
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    def container_logs(self, cid: str, tail: int = 500) -> str:
        """Return the last *tail* lines of container logs.

        Both stdout and stderr streams are captured and merged.
        """
        result = self.run_cmd(
            ["logs", "--tail", str(tail), cid],
            timeout=30,
        )
        # Docker writes most log output to stderr for containers
        return result.stdout + result.stderr

    def grep_logs(
        self,
        cid: str,
        pattern: str,
        tail: int = 1000,
    ) -> bool:
        """Check whether *pattern* appears in the container's recent logs.

        This replaces the duplicated ``check_plugin_in_logs()`` function
        that existed in two shell scripts.

        Parameters
        ----------
        cid:
            Container ID or name.
        pattern:
            Plain substring to search for (not a regex).
        tail:
            Number of log lines to inspect.

        Returns
        -------
        bool
            *True* if *pattern* was found.
        """
        logs = self.container_logs(cid, tail=tail)
        found = pattern in logs
        if found:
            logger.debug("Pattern %r found in logs of %s", pattern, cid[:12])
        else:
            logger.debug("Pattern %r NOT found in logs of %s", pattern, cid[:12])
        return found

    # ------------------------------------------------------------------
    # Exec
    # ------------------------------------------------------------------

    def exec_cmd(
        self,
        cid: str,
        command: str,
        timeout: int = 30,
        check: bool = True,
    ) -> str:
        """Execute a command inside a running container.

        Parameters
        ----------
        cid:
            Container ID or name.
        command:
            Shell command string (run via ``sh -c``).
        timeout:
            Maximum seconds to wait.
        check:
            If *True*, raise :class:`DockerError` on non-zero exit.

        Returns
        -------
        str
            Trimmed stdout of the command.
        """
        result = self.run_cmd(
            ["exec", cid, "sh", "-c", command],
            timeout=timeout,
            check=check,
        )
        return result.stdout.strip()

    def exec_test(self, cid: str, test_args: str) -> bool:
        """Run ``test <test_args>`` inside a container.

        Returns *True* if the test succeeds (exit code 0), *False*
        otherwise.  Never raises :class:`DockerError`.
        """
        result = self.run_cmd(
            ["exec", cid, "test", *test_args.split()],
            check=False,
            timeout=15,
        )
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Copy
    # ------------------------------------------------------------------

    def cp(self, src: str, dst: str, timeout: int = 30) -> None:
        """Copy files between a container and the local filesystem.

        Parameters
        ----------
        src:
            Source path (``container:path`` or local path).
        dst:
            Destination path (``container:path`` or local path).
        """
        self.run_cmd(["cp", src, dst], timeout=timeout)

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def ps(
        self,
        *,
        filter_name: str = "",
        quiet: bool = False,
    ) -> str:
        """Run ``docker ps`` with optional filters.

        Parameters
        ----------
        filter_name:
            If non-empty, filter by container name prefix.
        quiet:
            If *True*, return only container IDs (``-q``).

        Returns
        -------
        str
            The raw stdout of ``docker ps``.
        """
        args: list[str] = ["ps"]
        if quiet:
            args.append("-q")
        if filter_name:
            args.extend(["-f", f"name={filter_name}"])
        result = self.run_cmd(args, check=False, timeout=15)
        return result.stdout.strip()

    def system_prune(
        self,
        *,
        force: bool = True,
        filters: list[str] | None = None,
    ) -> None:
        """Run ``docker system prune``.

        Parameters
        ----------
        force:
            Pass ``-f`` to skip the confirmation prompt.
        filters:
            List of ``--filter`` arguments (e.g. ``["until=24h"]``).
        """
        args = ["system", "prune"]
        if force:
            args.append("-f")
        for f in filters or []:
            args.extend(["--filter", f])
        self.run_cmd(args, check=False, timeout=60)

    # ------------------------------------------------------------------
    # Convenience: run-and-remove (for init containers)
    # ------------------------------------------------------------------

    def run_ephemeral(
        self,
        image: str,
        *,
        volumes: dict[str, str] | None = None,
        env: dict[str, str] | None = None,
        command: str | list[str] | None = None,
        entrypoint: str | None = None,
        timeout: int = 120,
    ) -> str:
        """Run a container with ``--rm`` and return its stdout.

        This is intended for one-shot operations like ``gerrit init``
        that need to run inside the Gerrit image and then be discarded.

        Parameters
        ----------
        image:
            Docker image to run.
        volumes:
            Host→container volume mounts.
        env:
            Environment variables.
        command:
            Command to run.
        entrypoint:
            Override the image entrypoint.
        timeout:
            Maximum seconds to wait.

        Returns
        -------
        str
            The stdout output of the container.
        """
        args: list[str] = ["run", "--rm"]

        if entrypoint is not None:
            args.extend(["--entrypoint", entrypoint])
        for host_path, container_path in (volumes or {}).items():
            if ":ro" in host_path:
                base_path = host_path.replace(":ro", "")
                args.extend(["-v", f"{base_path}:{container_path}:ro"])
            else:
                args.extend(["-v", f"{host_path}:{container_path}"])
        for key, value in (env or {}).items():
            args.extend(["-e", f"{key}={value}"])

        args.append(image)

        if command:
            if isinstance(command, str):
                args.append(command)
            else:
                args.extend(command)

        result = self.run_cmd(args, timeout=timeout)
        return result.stdout
