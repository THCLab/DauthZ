# Minimal runtime for host-built binaries (cyfron-serviced and dauthz-gate)
# that docker-compose bind-mounts in. archlinux:base matches the host's
# glibc, avoiding `GLIBC_x.y not found` on a debian-slim base; openssl and
# ca-certificates serve the daemon's TLS calls to witnesses, curl the
# healthchecks.
FROM archlinux:base
RUN pacman -Sy --noconfirm --needed openssl ca-certificates curl dbus && \
    pacman -Scc --noconfirm
