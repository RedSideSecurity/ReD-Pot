#!/usr/bin/env bash
# ReD-Pot installer — interactive by default.
#   sudo ./install.sh                     menu
#   sudo ./install.sh manager             manager + decoys on this server
#   sudo ./install.sh sensor              remote sensor: paste the join string when asked
#                                      (unattended: --join-file FILE (chmod 600) or --join - on stdin;
#                                       never --join 'redpot://…' on the command line: ps shows it)
#   sudo ./install.sh add-decoy           add one decoy (e.g. on a new interface) — keeps persona + baits
#   sudo ./install.sh remove-decoy NAME   remove a decoy added earlier
#   sudo ./install.sh uninstall [--keep-data] [--purge-image]   (restores host SSH to 22)
#   sudo ./install.sh reset-token [--wall] [--wall-allow 10.0.5.20,10.0.6.0/28]
#                                      new admin token (+ new wall link, logs out all wall screens)
#   sudo ./install.sh geoip               download the GeoIP database later (world attack map)
#   sudo ./install.sh export --from YYYY-MM-DD --to YYYY-MM-DD [-o FILE] [--force]
#                                      JSON export of incidents + alert records (file mode 0600)
#   add --help for every unattended option, --dry-run to preview
set -euo pipefail
export RPOT_CWD="$PWD"   # export -o FILE / the default file are relative to where the user ran us
cd "$(dirname "$(readlink -f "$0")")"
if ! command -v python3 >/dev/null; then
  echo "python3 is required (apt-get install -y python3)"; exit 1
fi
exec python3 installer/redpot_install.py "$@"
