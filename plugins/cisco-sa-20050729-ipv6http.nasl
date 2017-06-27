#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20050729-ipv6.html
#
# @DEPRECATED@
#
# Disabled on 2011/12/07. Deprecated by cisco-sa-20050729-ipv6.nasl

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(54833);
 script_version("$Revision: 1.6 $");
 script_name(english:"IPv6 Crafted Packet Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software is vulnerable to a
Denial of Service (DoS) and potentially an arbitrary code execution
attack from a specially crafted IPv6 packet. The packet must be sent
from a local network segment. Only devices that have been explicitly
configured to process IPv6 traffic are affected. Upon successful
exploitation, the device may reload or be open to further exploitation.
Cisco has made free software available to address this vulnerability
for all affected customers.
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f9362391");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?becceb7b");
 script_set_attribute(attribute:"solution", value: "Apply the described patch (see plugin output).");
 script_set_attribute(attribute:"risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCef68324");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh74956");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20050729-ipv6");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

exit(0, "This plugin has been deprecated. Use cisco-sa-20050729-ipv6.nasl (plugin ID 48987) instead");

include("cisco_func.inc");

#

version = get_kb_item("Host/Cisco/IOS/Version");
if ( ! version ) exit(0);

# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(26)S6", "12.0(27)S5", "12.0(28)S3", "12.0(30)S2"),
                  newest: "12.0(31)S" )) {
 security_hole(0, extra: "Update to 12.0(31)S or later"); exit(0);
}
if (deprecated_version(version, "12.0SL")) {
 security_hole(0, extra: "Migrate to 12.0(31)S or later"); exit(0);
}
if (deprecated_version(version, "12.0ST")) {
 security_hole(0, extra: "Migrate to 12.0(31)S or later"); exit(0);
}
if (deprecated_version(version, "12.0SY")) {
 security_hole(0, extra: "Migrate to 12.0(31)S or later"); exit(0);
}
if (deprecated_version(version, "12.1XU")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1XV")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YB")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YC")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YD")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YE")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YF")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YH")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.1YI")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2B")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(15)BC2h") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2BW")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2BY")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2BX")) {
 security_hole(0, extra: "Migrate to 12.3(7)XI4 or later"); exit(0);
}
if (deprecated_version(version, "12.2BZ")) {
 security_hole(0, extra: "Migrate to 12.3(7)XI4 or later"); exit(0);
}
if (deprecated_version(version, "12.2CX")) {
 security_hole(0, extra: "Migrate to 12.3(13a or later"); exit(0);
}
if (deprecated_version(version, "12.2CY")) {
 security_hole(0, extra: "Migrate to 12.3(13a or later"); exit(0);
}
if (deprecated_version(version, "12.2DD")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2DX")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.2EU
if (check_release(version: version,
                  patched: make_list("12.2(20)EU1") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2EW
if (check_release(version: version,
                  patched: make_list("12.2(20)EW2") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(20)EWA2", "12.2(25)EWA1") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2EZ
if (check_release(version: version,
                  patched: make_list("12.2(25)EZ1") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2JA")) {
 security_hole(0, extra: "Migrate to 12.3(4)JA or later"); exit(0);
}
# Affected: 12.2JK
if (check_release(version: version,
                  patched: make_list("12.2(15)JK4") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB13b") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2MC
if (check_release(version: version,
                  patched: make_list("12.2(15)MC2c") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2MX")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S14", "12.2(18)S9", "12.2(20)S8", "12.2(25)S4") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2SEB
if (check_release(version: version,
                  patched: make_list("12.2(25)SEB3") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2SEC
if (check_release(version: version,
                  patched: make_list("12.2(25)SEC1") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2SU")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.2SV
if (check_release(version: version,
                  patched: make_list("12.2(18)SV3", "12.2(22)SV1", "12.2(23)SV1", "12.2(24)SV1", "12.2(25)SV2"),
                  newest: "12.2(26)SV" )) {
 security_hole(0, extra: "Update to 12.2(26)SV or later"); exit(0);
}
# Affected: 12.2SW
if (check_release(version: version,
                  patched: make_list("12.2(25)SW3a") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2SX")) {
 security_hole(0, extra: "Migrate to 12.2(17d or later"); exit(0);
}
if (deprecated_version(version, "12.2SXA")) {
 security_hole(0, extra: "Migrate to 12.2(17d or later"); exit(0);
}
# Affected: 12.2SXB
if (check_release(version: version,
                  patched: make_list("12.2(17d)SXB8") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2SXD
if (check_release(version: version,
                  patched: make_list("12.2(18)SXD4") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2SXE
if (check_release(version: version,
                  patched: make_list("12.2(18)SXE1") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2SY")) {
 security_hole(0, extra: "Migrate to 12.2(17d or later"); exit(0);
}
if (deprecated_version(version, "12.2SZ")) {
 security_hole(0, extra: "Migrate to 12.2(20)S8 or later"); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(13)T16", "12.2(15)T16") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2XA")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XB")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2XD")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XE")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_hole(0, extra: "Migrate to 12.3(13a or later"); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XH")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XI")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XJ")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XK")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XL")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XN")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XQ")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XR")) {
 security_hole(0, extra: "Migrate to 12.3(4)JA or later"); exit(0);
}
if (deprecated_version(version, "12.2XT")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XU")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XW")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2XZ")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA10") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2YB")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YC")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YE")) {
 security_hole(0, extra: "Migrate to 12.2(25)S4 or later"); exit(0);
}
if (deprecated_version(version, "12.2YF")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YG")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YH")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YJ")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YK")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YL")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YM")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YO")) {
 security_hole(0, extra: "Migrate to 12.2(17d or later"); exit(0);
}
if (deprecated_version(version, "12.2YP")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2YQ")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YR")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YT")) {
 security_hole(0, extra: "Migrate to 12.2(15)T16 or later"); exit(0);
}
if (deprecated_version(version, "12.2YU")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YV")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YW")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YX")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YY")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2YZ")) {
 security_hole(0, extra: "Migrate to 12.2(20)S8 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZA")) {
 security_hole(0, extra: "Migrate to 12.2(17d or later"); exit(0);
}
if (deprecated_version(version, "12.2ZB")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZC")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.2ZD
if (check_release(version: version,
                  patched: make_list("12.2(13)ZD3") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2ZE")) {
 security_hole(0, extra: "Migrate to 12.3(15) or later"); exit(0);
}
if (deprecated_version(version, "12.2ZF")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZH")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZJ")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZN")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZO")) {
 security_hole(0, extra: "Migrate to 12.2(15)T16 or later"); exit(0);
}
if (deprecated_version(version, "12.2ZP")) {
 security_hole(0, extra: "Migrate to 12.3(8)XY6 or later"); exit(0);
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(3h)", "12.3(5e)", "12.3(6e)", "12.3(9d)", "12.3(10d)", "12.3(12b)", "12.3(13a)"),
                  newest: "12.3(15)" )) {
 security_hole(0, extra: "Update to 12.3(15) or later"); exit(0);
}
# Affected: 12.3B
if (check_release(version: version,
                  patched: make_list("12.3(5a)B5") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(9a)BC6"),
                  newest: "12.3(13a)BC" )) {
 security_hole(0, extra: "Update to 12.3(13a)BC or later"); exit(0);
}
if (deprecated_version(version, "12.3BW")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.3JA
if (check_release(version: version,
                  newest: "12.3(4)JA" )) {
 security_hole(0, extra: "Update to 12.3(4)JA or later"); exit(0);
}
# Affected: 12.3JK
if (check_release(version: version,
                  newest: "12.3(2)JK" )) {
 security_hole(0, extra: "Update to 12.3(2)JK or later"); exit(0);
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(7)T9") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3XA
if (check_release(version: version,
                  patched: make_list("12.3(2)XA4") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XB")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.3XC
if (check_release(version: version,
                  patched: make_list("12.3(2)XC3") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3XE
if (check_release(version: version,
                  patched: make_list("12.3(2)XE3") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XF")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.3XG
if (check_release(version: version,
                  patched: make_list("12.3(4)XG4") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XH")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI4") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XJ")) {
 security_hole(0, extra: "Migrate to 12.3(11)YF3 or later"); exit(0);
}
# Affected: 12.3XK
if (check_release(version: version,
                  patched: make_list("12.3(4)XK3") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XM")) {
 security_hole(0, extra: "Migrate to 12.3(14)T2 or later"); exit(0);
}
# Affected: 12.3XQ
if (check_release(version: version,
                  patched: make_list("12.3(4)XQ1") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3XR
if (check_release(version: version,
                  patched: make_list("12.3(7)XR4") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XS")) {
 security_hole(0, extra: "Migrate to 12.4(1) or later"); exit(0);
}
if (deprecated_version(version, "12.3XU")) {
 security_hole(0, extra: "Migrate to 12.4(2)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XW")) {
 security_hole(0, extra: "Migrate to 12.3(11)YF3 or later"); exit(0);
}
if (deprecated_version(version, "12.3XX")) {
 security_hole(0, extra: "Migrate to 12.4(1) or later"); exit(0);
}
# Affected: 12.3XY
if (check_release(version: version,
                  patched: make_list("12.3(8)XY6") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3YA
if (check_release(version: version,
                  patched: make_list("12.3(8)YA1") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3YD")) {
 security_hole(0, extra: "Migrate to 12.4(2)T or later"); exit(0);
}
# Affected: 12.3YF
if (check_release(version: version,
                  patched: make_list("12.3(11)YF3") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3YG
if (check_release(version: version,
                  patched: make_list("12.3(8)YG2") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3YH")) {
 security_hole(0, extra: "Migrate to 12.3(8)YI1 or later"); exit(0);
}
# Affected: 12.3YI
if (check_release(version: version,
                  patched: make_list("12.3(8)YI1") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3YJ
if (check_release(version: version,
                  patched: make_list("12.3(11)YJ") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3YQ
if (check_release(version: version,
                  patched: make_list("12.3(14)YQ1") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3YS
if (check_release(version: version,
                  newest: "12.3(11)YS" )) {
 security_hole(0, extra: "Update to 12.3(11)YS or later"); exit(0);
}
# Affected: 12.3YT
if (check_release(version: version,
                  newest: "12.3(14)YT" )) {
 security_hole(0, extra: "Update to 12.3(14)YT or later"); exit(0);
}
# Affected: 12.3YU
if (check_release(version: version,
                  newest: "12.3(14)YU" )) {
 security_hole(0, extra: "Update to 12.3(14)YU or later"); exit(0);
}
# Affected: 12.4
if (check_release(version: version,
                  newest: "12.4(1)" )) {
 security_hole(0, extra: "Update to 12.4(1) or later"); exit(0);
}
# Affected: 12.4MR
if (check_release(version: version,
                  newest: "12.4(2)MR" )) {
 security_hole(0, extra: "Update to 12.4(2)MR or later"); exit(0);
}
# Affected: 12.4T
if (check_release(version: version,
                  newest: "12.4(2)T" )) {
 security_hole(0, extra: "Update to 12.4(2)T or later"); exit(0);
}

exit(0, "The remote host is not affected");
