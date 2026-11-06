#!/bin/bash
# Security probes, run in a test VM as insasse (sudo works, as for an agent).
# Prints one line per check: PASS|FAIL|SKIP <id> <detail>. Never stops early.
#
# Inputs (prepended by the harness):
#   REPO_DIR     the fixture clone
#   HOST_PORT    a TCP port the host listens on (all interfaces)
#   HOST_IPS     the host's addresses
#   PEER_IP      another test VM, PEER_PORT a port it listens on
#
# Markers are regexes ("wz[l]eak") so no process, not even the grep looking
# for them, has the marker itself in its command line.
set -u
LEAK="wz[l]eak"
HOST_SENTINEL="wz[h]ostcfg"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1 ${2:-}" | tr '\n' ' '; echo; }

# ok <id> <cmd…>: the command must succeed.
ok() {
  local id=$1 out; shift
  if out=$("$@" 2>&1); then pass "$id"; else fail "$id" "$(tail -n 2 <<<"$out")"; fi
}

# denied <id> <cmd…>: the command must fail.
denied() {
  local id=$1 out; shift
  if out=$("$@" 2>&1); then fail "$id" "succeeded: $(tail -n 2 <<<"$out")"; else pass "$id"; fi
}

fetch() { curl -fsS --max-time 15 -o /dev/null "$@"; }
tcp() { timeout 5 bash -c "echo probe >/dev/tcp/$1/$2"; }

# resolves_via <server> <name>: an A query over TCP straight to <server>,
# bypassing the guest's resolver. Succeeds if it gets an answer.
resolves_via() {
  perl -MIO::Socket::INET -e '
    my ($srv, $name) = @ARGV;
    my $s = IO::Socket::INET->new(PeerAddr => $srv, PeerPort => 53, Proto => "tcp", Timeout => 5) or exit 1;
    my $q = pack("n6", 0x1234, 0x0100, 1, 0, 0, 0)
      . join("", map { chr(length) . $_ } split /\./, $name) . "\0" . pack("n2", 1, 1);
    print $s pack("n", length $q) . $q;
    read($s, my $len, 2) == 2 or exit 1;
    read($s, my $r, unpack("n", $len));
    my (undef, $flags, undef, $answers) = unpack("n4", $r);
    exit(($flags & 15) == 0 && $answers > 0 ? 0 : 1);' "$1" "$2"
}

# --- Egress ---------------------------------------------------------------
ok     egress.allowed_https   fetch https://api.github.com/zen
ok     egress.allowed_dns     getent ahosts github.com
denied egress.denied_https    fetch https://example.com
denied egress.denied_http     fetch http://example.com
denied egress.denied_dns      getent ahosts example.com
denied egress.raw_ip_https    fetch -k https://1.1.1.1
denied egress.raw_ip_http     fetch http://1.1.1.1
# Port 53 to any address is intercepted and filtered by name.
nameserver=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
ok     egress.dns_query       resolves_via "$nameserver" github.com
denied egress.direct_dns      resolves_via 8.8.8.8 example.com
denied egress.ipv6            fetch -k "https://[2606:4700:4700::1111]"
denied egress.metadata        fetch http://169.254.169.254/latest/meta-data/
# A denied target that shares an allowed IP must stay denied (SNI/Host).
denied egress.wrong_sni       fetch --resolve example.com:443:"$(getent ahosts github.com | awk 'NR==1{print $1}')" https://example.com

# --- Host access ----------------------------------------------------------
gateway=$(awk 'NR>1 && $2=="00000000" {print $3}' /proc/net/route | head -n 1 \
  | sed -E 's/(..)(..)(..)(..)/0x\4 0x\3 0x\2 0x\1/' | xargs printf '%d.%d.%d.%d')
for ip in "$gateway" host.microsandbox.internal $HOST_IPS; do
  denied "host.port_${ip}" tcp "$ip" "$HOST_PORT"
done
denied host.peer_vm tcp "$PEER_IP" "$PEER_PORT"

# --- Host exposure --------------------------------------------------------
mounts=$(awk '$3=="virtiofs" || $3=="9p" || $3=="fuse" {print $2}' /proc/mounts | tr '\n' ' ')
if [ "$mounts" = "/.msb " ]; then pass exposure.shared_mounts; else fail exposure.shared_mounts "$mounts"; fi

msb_entries=$(ls -A /.msb | tr '\n' ' ')
expected="checkpoint-store checkpoints heartbeat.json owned-disks root-disk.json rootfs runtime-boot-id scripts tls "
if [ "$msb_entries" = "$expected" ]; then pass exposure.msb_entries; else fail exposure.msb_entries "$msb_entries"; fi
tls_entries=$(ls -A /.msb/tls | tr '\n' ' ')
if [ "$tls_entries" = "ca.pem " ]; then pass exposure.msb_tls; else fail exposure.msb_tls "$tls_entries"; fi
sockets=$(sudo find /.msb -type s 2>/dev/null)
if [ -z "$sockets" ]; then pass exposure.msb_sockets; else fail exposure.msb_sockets "$sockets"; fi

# Places the host could have written to, plus every process's env and args.
search_dirs="/.msb /etc /home /root /run /tmp /work /var/log /opt /usr/local"
leaks() {
  sudo grep -rlsI --exclude-dir=proc "$1" $search_dirs 2>/dev/null | head -n 3
  sudo grep -ls "$1" /proc/[0-9]*/environ /proc/[0-9]*/cmdline 2>/dev/null | head -n 3
}
found=$(leaks "$HOST_SENTINEL")
if [ -z "$found" ]; then pass exposure.host_config; else fail exposure.host_config "$found"; fi
denied exposure.herdr_config test -e ~/.config/herdr/config.toml

# --- Secrets --------------------------------------------------------------
for var in GH_TOKEN CLAUDE_CODE_OAUTH_TOKEN; do
  if [ "${!var:-}" = "\$MSB_$var" ]; then pass "secrets.placeholder_$var"; else fail "secrets.placeholder_$var" "${!var:-unset}"; fi
done
found=$(leaks "$LEAK")
if [ -z "$found" ]; then pass secrets.no_values; else fail secrets.no_values "$found"; fi

# --- Docker and the CA wrapper --------------------------------------------
img=curlimages/curl:8.10.1
ok     docker.run_https     docker run --rm "$img" -fsS --max-time 15 -o /dev/null https://api.github.com/zen
denied docker.run_denied    docker run --rm "$img" -fsS --max-time 10 -o /dev/null https://example.com
ok     docker.build_https   docker build -q --no-cache "$REPO_DIR"

ip2int() { local IFS=.; set -- $1; echo $(( ($1<<24) + ($2<<16) + ($3<<8) + $4 )); }
in_cidr() { # ip net/len
  local n=${2%/*} len=${2#*/}
  local mask=$(( len == 0 ? 0 : (0xffffffff << (32 - len)) & 0xffffffff ))
  (( ($(ip2int "$1") & mask) == ($(ip2int "$n") & mask) ))
}
guest_ip=$(hostname -I | awk '{print $1}')
overlap=""
for net in $(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $(docker network ls -q)); do
  [[ $net == *:* ]] && continue
  for ip in "$guest_ip" "$gateway"; do in_cidr "$ip" "$net" && overlap+="$ip in $net "; done
done
if [ -z "$overlap" ]; then pass docker.no_overlap; else fail docker.no_overlap "$overlap"; fi

# --- Provisioning ---------------------------------------------------------
ok provision.toolchain bash -c "cd '$REPO_DIR' && mise exec -- rg --version"
ok provision.gh bash -c "command -v gh || mise which gh"
