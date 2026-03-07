#!/usr/bin/env bash
#
# usage nft-blacklist.sh <configuration file>
# eg: nft-blacklist.sh /etc/nft-blacklist/nft-blacklist.conf
#

# can be executable name or custom path of either `iprange`
# (not IPv6 support: https://github.com/firehol/iprange/issues/14)
# * or `cidr-merger` (https://github.com/zhanhb/cidr-merger)
# * or `aggregate-prefixes` (Python)
DEFAULT_CIDR_MERGER=cidr-merger
NFT=nft            # can be "sudo /sbin/nft" or whatever to apply the ruleset
DEFAULT_HOOK=input # use "prerouting" if you need to drop packets before other prerouting rule chains
DEFAULT_CHAIN=input
SET_NAME_PREFIX=blacklist
SET_NAME_V4="${SET_NAME_PREFIX}_v4"
SET_NAME_V6="${SET_NAME_PREFIX}_v6"
IPV4_REGEX="(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{2})?"
IPV6_REGEX="(?:(?:[0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,7}:|\
(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|\
(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|\
(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|\
(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|\
[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|\
:(?:(?::[0-9a-f]{1,4}){1,7}|:)|\
::(?:[f]{4}(?::0{1,4})?:)?\
(?:(25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|\
(?:[0-9a-f]{1,4}:){1,4}:\
(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\
(?:/[0-9]{1,3})?"

function exists() { command -v "$1" >/dev/null 2>&1; }
function count_entries() { awk 'END { print NR }' "$1"; }
function collapse_prefixes_python() {
	local input_file=$1
	local output_file=$2
	local family=$3
	python3 - "${input_file}" "${output_file}" "${family}" <<'PY'
import ipaddress
import sys

input_file, output_file, family = sys.argv[1:]
wanted = int(family)
networks = []

with open(input_file, encoding="utf-8") as f:
	for raw in f:
		line = raw.strip()
		if not line or line.startswith(("#", ";", "$")):
			continue
		try:
			net = ipaddress.ip_network(line, strict=False)
		except ValueError:
			continue
		if net.version == wanted:
			networks.append(net)

collapsed = ipaddress.collapse_addresses(networks)
with open(output_file, "w", encoding="utf-8") as f:
	for net in collapsed:
		if (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128):
			f.write(f"{net.network_address}\n")
		else:
			f.write(f"{net.with_prefixlen}\n")
PY
}

if [[ -z $1 ]]; then
	echo "Error: please specify a configuration file, e.g. $0 /etc/nft-blacklist/nft-blacklist.conf"
	exit 1
fi

# shellcheck source=nft-blacklist.conf
if ! source "$1"; then
	echo "Error: can't load configuration file $1"
	exit 1
fi

if ! type -P curl grep sed sort wc date &>/dev/null; then
	echo >&2 "Error: searching PATH fails to find executables among: curl grep sed sort wc date"
	exit 1
fi

if [[ ${VERBOSE:-no} =~ ^(1|on|true|yes)$ ]]; then
	VERBOSE=1
else
	VERBOSE=0
fi

if [[ ${DRY_RUN:-no} =~ ^(1|on|true|yes)$ ]]; then
	DRY_RUN=1
else
	DRY_RUN=0
fi

if [[ ${DO_OPTIMIZE_CIDR:-yes} =~ ^(1|on|true|yes)$ ]]; then
	OPTIMIZE_CIDR=1
else
	OPTIMIZE_CIDR=0
fi

if [[ ${KEEP_TMP_FILES:-no} =~ ^(1|on|true|yes)$ ]]; then
	KEEP_TMP_FILES=1
else
	KEEP_TMP_FILES=0
fi
CIDR_MERGER="${CIDR_MERGER:-${DEFAULT_CIDR_MERGER}}"
HOOK="${HOOK:-${DEFAULT_HOOK}}"
CHAIN="${CHAIN:-${DEFAULT_CHAIN}}"

if exists "${CIDR_MERGER}" && ((OPTIMIZE_CIDR)); then
	OPTIMIZE_CIDR=1
elif ((OPTIMIZE_CIDR)); then
	OPTIMIZE_CIDR=0
	echo >&2 "Warning: ${CIDR_MERGER} is not available"
fi

ip_blacklist_dir=$(dirname "${IP_BLACKLIST_FILE}")
ip6_blacklist_dir=$(dirname "${IP6_BLACKLIST_FILE}")
ruleset_dir=$(dirname "${RULESET_FILE}")
if [[ ! -d ${ip_blacklist_dir} || ! -d ${ip6_blacklist_dir} || ! -d ${ruleset_dir} ]]; then
	missing_dirs=()
	for d in "${ip_blacklist_dir}" "${ip6_blacklist_dir}" "${ruleset_dir}"; do
		if [[ " ${missing_dirs[*]} " != *" ${d} "* ]]; then
			missing_dirs+=("${d}")
		fi
	done
	echo >&2 "Error: missing directory(s): ${missing_dirs[*]}"
	exit 1
fi

((VERBOSE)) && echo -n "Processing ${#BLACKLISTS[@]} sources of blacklist: "

IP_BLACKLIST_TMP_FILE=$(mktemp -t nft-blacklist-ip-XXX)
IP6_BLACKLIST_TMP_FILE=$(mktemp -t nft-blacklist-ip6-XXX)
for url in "${BLACKLISTS[@]}"; do
	IP_TMP_FILE=$(mktemp -t nft-blacklist-source-XXX)
	HTTP_RC=$(curl -L -A "nft-blacklist/1.0 (https://github.com/leshniak/nft-blacklist)" --connect-timeout 10 --max-time 10 -o "${IP_TMP_FILE}" -s -w "%{http_code}" "${url}")
	# On file:// protocol, curl returns "000" per-file (file:///tmp/[1-3].txt would return "000000000" whether the 3 files exist or not)
	# A sequence of 3 resources would return "200200200"
	if ((HTTP_RC == 200 || HTTP_RC == 302)) || [[ ${HTTP_RC} =~ ^(000|200){1,}$ ]]; then
		IP_TMP_V4_FILE=$(mktemp -t nft-blacklist-source-v4-XXX)
		command grep -Po "^${IPV4_REGEX}" "${IP_TMP_FILE}" >"${IP_TMP_V4_FILE}" || true
		sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' "${IP_TMP_V4_FILE}" >>"${IP_BLACKLIST_TMP_FILE}"
		rm -f "${IP_TMP_V4_FILE}"
		command grep -Pio "^${IPV6_REGEX}" "${IP_TMP_FILE}" >>"${IP6_BLACKLIST_TMP_FILE}"
		((VERBOSE)) && echo -n "."
	elif ((HTTP_RC == 503)); then
		echo -e "\\nUnavailable (${HTTP_RC}): ${url}"
	else
		echo >&2 -e "\\nWarning: curl returned HTTP response code ${HTTP_RC} for URL ${url}"
	fi
	((KEEP_TMP_FILES)) || rm -f "${IP_TMP_FILE}"
done

((VERBOSE)) && echo -e '\n'

# sort -nu does not work as expected
IP_BLACKLIST_FILTERED_TMP_FILE=$(mktemp -t nft-blacklist-ip-filtered-XXX)
IP_BLACKLIST_SORTED_TMP_FILE=$(mktemp -t nft-blacklist-ip-sorted-XXX)
IP6_BLACKLIST_FILTERED_TMP_FILE=$(mktemp -t nft-blacklist-ip6-filtered-XXX)
IP6_BLACKLIST_SORTED_TMP_FILE=$(mktemp -t nft-blacklist-ip6-sorted-XXX)
sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' "${IP_BLACKLIST_TMP_FILE}" >"${IP_BLACKLIST_FILTERED_TMP_FILE}"
sort -n "${IP_BLACKLIST_FILTERED_TMP_FILE}" >"${IP_BLACKLIST_SORTED_TMP_FILE}"
sort -mu "${IP_BLACKLIST_SORTED_TMP_FILE}" >|"${IP_BLACKLIST_FILE}"
sed -r -e '/^([0:]+\/0|fe80:)/Id' "${IP6_BLACKLIST_TMP_FILE}" >"${IP6_BLACKLIST_FILTERED_TMP_FILE}"
sort -d "${IP6_BLACKLIST_FILTERED_TMP_FILE}" >"${IP6_BLACKLIST_SORTED_TMP_FILE}"
sort -mu "${IP6_BLACKLIST_SORTED_TMP_FILE}" >|"${IP6_BLACKLIST_FILE}"
if ((OPTIMIZE_CIDR)); then
	ip_v4_count=$(count_entries "${IP_BLACKLIST_FILE}")
	ip_v6_count=$(count_entries "${IP6_BLACKLIST_FILE}")
	((VERBOSE)) && echo -e "Optimizing entries...\\nFound: ${ip_v4_count} IPv4, ${ip_v6_count} IPv6"
	if [[ ${CIDR_MERGER} =~ merger ]]; then
		${CIDR_MERGER} -o "${IP_BLACKLIST_TMP_FILE}" -o "${IP6_BLACKLIST_TMP_FILE}" "${IP_BLACKLIST_FILE}" "${IP6_BLACKLIST_FILE}"
	elif [[ ${CIDR_MERGER} =~ iprange ]]; then
		${CIDR_MERGER} --optimize "${IP_BLACKLIST_FILE}" >"${IP_BLACKLIST_TMP_FILE}"
		${CIDR_MERGER} --optimize "${IP6_BLACKLIST_FILE}" >"${IP6_BLACKLIST_TMP_FILE}"
	elif [[ ${CIDR_MERGER} =~ aggregate-prefixes ]]; then
		${CIDR_MERGER} -s "${IP_BLACKLIST_FILE}" >"${IP_BLACKLIST_TMP_FILE}"
		${CIDR_MERGER} -s "${IP6_BLACKLIST_FILE}" >"${IP6_BLACKLIST_TMP_FILE}"
	fi
	ip_v4_saved_count=$(count_entries "${IP_BLACKLIST_TMP_FILE}")
	ip_v6_saved_count=$(count_entries "${IP6_BLACKLIST_TMP_FILE}")
	((VERBOSE)) && echo -e "Saved: ${ip_v4_saved_count} IPv4, ${ip_v6_saved_count} IPv6\\n"
	cp "${IP_BLACKLIST_TMP_FILE}" "${IP_BLACKLIST_FILE}"
	cp "${IP6_BLACKLIST_TMP_FILE}" "${IP6_BLACKLIST_FILE}"
fi

# Final canonicalization pass: removes duplicates and overlaps
# (e.g. an IP already covered by a CIDR) to avoid nft EEXIST failures.
if exists python3; then
	IP_BLACKLIST_COLLAPSED_TMP_FILE=$(mktemp -t nft-blacklist-ip-collapsed-XXX)
	IP6_BLACKLIST_COLLAPSED_TMP_FILE=$(mktemp -t nft-blacklist-ip6-collapsed-XXX)
	if collapse_prefixes_python "${IP_BLACKLIST_FILE}" "${IP_BLACKLIST_COLLAPSED_TMP_FILE}" 4; then
		cp "${IP_BLACKLIST_COLLAPSED_TMP_FILE}" "${IP_BLACKLIST_FILE}"
	fi
	if collapse_prefixes_python "${IP6_BLACKLIST_FILE}" "${IP6_BLACKLIST_COLLAPSED_TMP_FILE}" 6; then
		cp "${IP6_BLACKLIST_COLLAPSED_TMP_FILE}" "${IP6_BLACKLIST_FILE}"
	fi
	((KEEP_TMP_FILES)) || rm -f "${IP_BLACKLIST_COLLAPSED_TMP_FILE}" "${IP6_BLACKLIST_COLLAPSED_TMP_FILE}"
elif ((VERBOSE)); then
	echo >&2 "Warning: python3 is not available; skipping final overlap collapse"
fi

((KEEP_TMP_FILES)) || rm -f "${IP_BLACKLIST_TMP_FILE}" "${IP6_BLACKLIST_TMP_FILE}"
((KEEP_TMP_FILES)) || rm -f "${IP_BLACKLIST_FILTERED_TMP_FILE}" "${IP_BLACKLIST_SORTED_TMP_FILE}" "${IP6_BLACKLIST_FILTERED_TMP_FILE}" "${IP6_BLACKLIST_SORTED_TMP_FILE}"

created_at=$(date -uIseconds)
ip_v4_entry_count=$(count_entries "${IP_BLACKLIST_FILE}")
ip_v6_entry_count=$(count_entries "${IP6_BLACKLIST_FILE}")
ip_whitelist_rule=''
if [[ -n ${IP_WHITELIST-} ]]; then
	ip_whitelist_rule=$'\n'"add rule inet ${TABLE} ${CHAIN} ip saddr { ${IP_WHITELIST} } accept"
fi
ip6_whitelist_rule=''
if [[ -n ${IP6_WHITELIST-} ]]; then
	ip6_whitelist_rule=$'\n'"add rule inet ${TABLE} ${CHAIN} ip6 saddr { ${IP6_WHITELIST} } accept"
fi

cat >|"${RULESET_FILE}" <<EOF
#
# Created by nft-blacklist (https://github.com/leshniak/nft-blacklist) at ${created_at}
# Blacklisted entries: ${ip_v4_entry_count} IPv4, ${ip_v6_entry_count} IPv6
#
# Sources used:
$(printf "#   - %s\n" "${BLACKLISTS[@]}")
#
add table inet ${TABLE}
add counter inet ${TABLE} ${SET_NAME_V4}
add counter inet ${TABLE} ${SET_NAME_V6}
add set inet ${TABLE} ${SET_NAME_V4} { type ipv4_addr; flags interval; auto-merge; }
flush set inet ${TABLE} ${SET_NAME_V4}
add set inet ${TABLE} ${SET_NAME_V6} { type ipv6_addr; flags interval; auto-merge; }
flush set inet ${TABLE} ${SET_NAME_V6}
add chain inet ${TABLE} ${CHAIN} { type filter hook ${HOOK} priority filter - 1; policy accept; }
flush chain inet ${TABLE} ${CHAIN}
add rule inet ${TABLE} ${CHAIN} iif "lo" accept
add rule inet ${TABLE} ${CHAIN} meta pkttype { broadcast, multicast } accept\
${ip_whitelist_rule}\
${ip6_whitelist_rule}
add rule inet ${TABLE} ${CHAIN} ip saddr @${SET_NAME_V4} counter name ${SET_NAME_V4} drop
add rule inet ${TABLE} ${CHAIN} ip6 saddr @${SET_NAME_V6} counter name ${SET_NAME_V6} drop
EOF

if [[ -s ${IP_BLACKLIST_FILE} ]]; then
	IP_V4_ELEMENTS_RAW_TMP_FILE=$(mktemp -t nft-blacklist-ipv4-elements-raw-XXX)
	IP_V4_ELEMENTS_NORM_TMP_FILE=$(mktemp -t nft-blacklist-ipv4-elements-norm-XXX)
	IP_V4_ELEMENTS_UNIQ_TMP_FILE=$(mktemp -t nft-blacklist-ipv4-elements-uniq-XXX)
	sed -rn -e '/^[#$;]/d' -e 's/^([0-9./]+).*/\1/p' "${IP_BLACKLIST_FILE}" >"${IP_V4_ELEMENTS_RAW_TMP_FILE}"
	sed -r 's#/32$##' "${IP_V4_ELEMENTS_RAW_TMP_FILE}" >"${IP_V4_ELEMENTS_NORM_TMP_FILE}"
	sort -u "${IP_V4_ELEMENTS_NORM_TMP_FILE}" >"${IP_V4_ELEMENTS_UNIQ_TMP_FILE}"
	{
		echo "add element inet ${TABLE} ${SET_NAME_V4} {"
		sed -r 's#^(.*)$#  \1,#' "${IP_V4_ELEMENTS_UNIQ_TMP_FILE}"
		echo "}"
	} >>"${RULESET_FILE}"
	((KEEP_TMP_FILES)) || rm -f "${IP_V4_ELEMENTS_RAW_TMP_FILE}" "${IP_V4_ELEMENTS_NORM_TMP_FILE}" "${IP_V4_ELEMENTS_UNIQ_TMP_FILE}"
fi

if [[ -s ${IP6_BLACKLIST_FILE} ]]; then
	IP_V6_ELEMENTS_RAW_TMP_FILE=$(mktemp -t nft-blacklist-ipv6-elements-raw-XXX)
	IP_V6_ELEMENTS_NORM_TMP_FILE=$(mktemp -t nft-blacklist-ipv6-elements-norm-XXX)
	IP_V6_ELEMENTS_UNIQ_TMP_FILE=$(mktemp -t nft-blacklist-ipv6-elements-uniq-XXX)
	sed -rn -e '/^[#$;]/d' -e "s/^(([0-9a-f:.]+:+[0-9a-f]*)+(\/[0-9]{1,3})?).*/\1/Ip" "${IP6_BLACKLIST_FILE}" >"${IP_V6_ELEMENTS_RAW_TMP_FILE}"
	sed -r 's#/128$##I' "${IP_V6_ELEMENTS_RAW_TMP_FILE}" >"${IP_V6_ELEMENTS_NORM_TMP_FILE}"
	sort -fu "${IP_V6_ELEMENTS_NORM_TMP_FILE}" >"${IP_V6_ELEMENTS_UNIQ_TMP_FILE}"
	{
		echo "add element inet ${TABLE} ${SET_NAME_V6} {"
		sed -r 's#^(.*)$#  \1,#' "${IP_V6_ELEMENTS_UNIQ_TMP_FILE}"
		echo "}"
	} >>"${RULESET_FILE}"
	((KEEP_TMP_FILES)) || rm -f "${IP_V6_ELEMENTS_RAW_TMP_FILE}" "${IP_V6_ELEMENTS_NORM_TMP_FILE}" "${IP_V6_ELEMENTS_UNIQ_TMP_FILE}"
fi

if ((!DRY_RUN)); then
	((VERBOSE)) && echo "Applying ruleset..."
	${NFT} -f "${RULESET_FILE}" || {
		echo >&2 "Failed to apply the ruleset"
		exit 1
	}
fi

((VERBOSE)) && echo "Done!"

exit 0
