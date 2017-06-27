#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00801a34c2.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48971);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0567");
 script_bugtraq_id(8211);
 script_osvdb_id(2325);
 script_xref(name:"CERT-CC", value:"411332");
 script_xref(name:"CERT-CC", value:"CA-2003-15");
 script_xref(name:"CERT-CC", value:"CA-2003-17");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdi22941");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx02283");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz71127");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea02355");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20030717-blocked");
 script_xref(name:"EDB-ID", value:"59");
 script_xref(name:"EDB-ID", value:"60");
 script_xref(name:"EDB-ID", value:"62");
 script_name(english:"Cisco IOS Interface Blocked by IPv4 Packets - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Cisco routers and switches running Cisco IOS software and configured
to process Internet Protocol version 4 (IPv4) packets are vulnerable to
a Denial of Service (DoS) attack. Multiple IPv4 packets with specific
protocol fields sent directly to the device may cause the input
interface to stop processing traffic once the input queue is full.
Traffic passing through the device cannot block the input queue. No
authentication is required to process the inbound packet. Processing of
IPv4 packets is enabled by default. Devices running only IP version 6
(IPv6) are not affected. Multiple valid workarounds are available in
the form of best practices for situations where software upgrades are
not currently feasible.
Cisco has made software available, free of charge, to correct the
problem.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20030717-blocked
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?5262d246");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00801a34c2.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?2c940981");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20030717-blocked."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/07/17");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Affected: 10.x
if (version =~ "^10\.") {
 security_hole(port:0, extra: '\nNo fix is available for 10.x releases. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.0
if (deprecated_version(version, "11.0")) {
 security_hole(port:0, extra: '\nNo fix is available for 11.0 releases. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.1
if (check_release(version: version,
                  patched: make_list("11.1(24c)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1AA
if (check_release(version: version,
                  patched: make_list("11.1(20)AA5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CA
if (check_release(version: version,
                  patched: make_list("11.1(36)CA4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC7") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(15b)", "11.2(26e)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(17)P1", "11.2(20)P1", "11.2(26)P5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2SA
if (check_release(version: version,
                  patched: make_list("11.2(8.11)SA6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3
if (check_release(version: version,
                  patched: make_list("11.3(11d)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3T
if (check_release(version: version,
                  patched: make_list("11.3(11b)T3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(15b)", "12.0(16b)", "12.0(19b)", "12.0(8b)", "12.0(26)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(10)DA2 / 12.2(12)DA3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(10)S3b", "12.0(10)S8", "12.0(12)S4", "12.0(13)S8", "12.0(14)S8", "12.0(15)S7", "12.0(16)S10", "12.0(16)S8a", "12.0(17)S7", "12.0(18)S5a", "12.0(18)S7", "12.0(19)S2a", "12.0(19)S4", "12.0(21)S4a", "12.0(21)S5a", "12.0(21)S7", "12.0(22)S5", "12.0(23)S3", "12.0(24)S2", "12.0(25)S"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(19)EC or later\n'); exit(0);
}
if (check_release(version: version,
                  patched: make_list("12.0(17)SL9") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (check_release(version: version,
                  patched: make_list("12.0(21)SP4") )) {
 security_hole(port:0, extra: '\nMigrate to 12.0(22)S5 or update to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(17)ST8", "12.0(19)ST6", "12.0(20)ST6", "12.0(21)ST3a", "12.0(21)ST7") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (version == '12.0(21)SX') {
 security_hole(port:0, extra: '\nUpdate to 12.0(22)S5 or later\n'); exit(0);
} 
if (version == '12.0(22)SX') {
 security_hole(port:0, extra: '\nNo fixes are available for 12.0(22)SX. Upgrade to a non-vulnerable version\n'); exit(0);
}
if (deprecated_version(version, "12.0SY")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(23)S3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(23)S3 or later\n'); exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(7)T3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0W5
if (
  "W5" >< version && # avoid flagging versions like W4
  check_release(version: version, patched: make_list("12.0(24)W5(26c)", "12.0(26)W5(28)", "12.0(25)W5(27)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0WT")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.0WT releases. Upgrade to a supported version\n'); exit(0);
}
# All 12.0X(any letter) releases have migrated to either 12.0T or 12.1 unless otherwise
# documented in the X release technical notes pertaining to the specific release.
# Please check migration paths for all 12.0X releases.
if (version =~ "^12\.0.+X[A-Z]") {
 security_hole(port:0, extra:
   '\n12.0X releases are no longer supported unless otherwise noted.' +
   '\nCheck the migration paths for all 12.0X releases\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(13a)", "12.1(17a)", "12.1(4b)", "12.1(6b)", "12.1(18.4)", "12.1(19)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17) or later\n'); exit(0);
}
# Affected: 12.1AX
if (deprecated_version(version, "12.1AX")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(14)EA1 or later\n'); exit(0);
}
# Affected: 12.1AY
if (check_release(version: version,
                  patched: make_list("12.1(13)AY"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(10)DA2 / 12.2(12)DA3 or later\n'); exit(0);
}
# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(5)DB2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(5)DC3"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(6)E12", "12.1(7a)E1a", "12.1(8b)E14", "12.1(11b)E12", "12.1(12c)E7", "12.1(13)E7", "12.1(14)E4", "12.1(10)E6a", "12.1(11b)E0a", "12.1(7)E0a", "12.1(19)E"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (
  version == "12.1(4)EA" ||
  version == "12.1(6)EA" ||
  version == "12.1(8)EA" ||
  version == "12.1(9)EA" ||
  version == "12.1(11)EA" ||
  version == "12.1(12c)EA" ||
  version == "12.1(13)EA"
) {
 security_hole(port:0, extra: '\nUpdate to 12.1(13)EA1c or later\n'); exit(0);
}
# Affected: 12.1EB
if (check_release(version: version,
                  patched: make_list("12.1(14)EB"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(13)EC4", "12.1(19)EC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EV
if (check_release(version: version,
                  patched: make_list("12.1(12c)EV2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(12c)EW2", "12.1(13)EW2", "12.1(19)EW"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# 12.1(1)EX to 12.1(8b)EX5 Migrate to 12.1(8b)E14
if (
 check_release(version: version, patched: make_list("12.1(8b)EX5")) ||
 version == '12.1(8b)EX5'
) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# 12.1(9)EX to current - To be determined (this should cover everything 12.1EX not caught by the check above)
if (deprecated_version(version, "12.1EX")) {
 security_hole(port:0, extra: '\nNo fixes are available for releases 12.1(9)EX and later. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1EY
if (deprecated_version(version, "12.1EY")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(14)E4 / 12.1(14)EB (LS1010 ONLY) or later\n'); exit(0);
}
# Affected: 12.1YJ
if (deprecated_version(version, "12.1YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(14)EA1 or later\n'); exit(0);
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(5)T15", "12.1(5)T8c") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(11)T9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XC", "12.1XD", "12.1XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17) or later\n'); exit(0);
}
# Affected: 12.1XI
if (check_release(version: version,
                  patched: make_list("12.1(3a)XI9") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XB", "12.1XF", "12.1XG", "12.1XJ", "12.1XL", "12.1XP", "12.1XR", "12.1XT", "12.1YB", "12.1YC", "12.1YD", "12.1YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XM", "12.1XQ", "12.1XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(2)XB11 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(4)T6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YE", "12.1YF", "12.1YI")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(2)YC or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10d)", "12.2(12e)", "12.2(13b)M2", "12.2(16a)", "12.2(6j)", "12.2(7g)", "12.2(17)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2B
# 12.2(2)B-12.2(4)B7
if (check_release(version: version,
                  patched: make_list("12.2(4)B7a"),
                  oldest:"12.2(2)B")) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# 12.2(4)B8-12.2(16)B
if (check_release(version: version,
                  patched: make_list("12.2(16)B1"),
                  oldest:"12.2(4)B8")) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(11)BC3c", "12.2(15)BC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
# Affected: 12.2BX
if (check_release(version: version,
                  patched: make_list("12.2(16)BX"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2BZ
if (check_release(version: version,
                  patched: make_list("12.2(15)BZ1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC1 or later\n'); exit(0);
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(10)DA2", "12.2(12)DA3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
# Affected: 12.2JA
if (check_release(version: version,
                  patched: make_list("12.2(11)JA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB12") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2MC
if (check_release(version: version,
                  patched: make_list("12.2(15)MC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2MX
if (deprecated_version(version, "12.2MX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(8)YD or later\n'); exit(0);
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S1", "12.2(16.5)S") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SX
if (check_release(version: version,
                  patched: make_list("12.2(14)SX1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SY
if (check_release(version: version,
                  patched: make_list("12.2(14)SY1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SZ
if (check_release(version: version,
                  patched: make_list("12.2(14)SZ2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(11)T9", "12.2(13)T1a", "12.2(13)T5", "12.2(15)T5", "12.2(4)T6", "12.2(8)T0c", "12.2(8)T10", "12.2(16.5)T"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(11)T9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(4)YA6 or later\n'); exit(0);
}
# Affected: 12.2XS
if (check_release(version: version,
                  patched: make_list("12.2(1)XS1a"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XD", "12.2XE", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XQ", "12.2XU", "12.2XW", "12.2YB", "12.2YC", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YT")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)T5 or later\n'); exit(0);
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(13)ZH2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YO")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(14)SY1 or later\n'); exit(0);
}
# Affected: 12.2XB
if (check_release(version: version,
                  patched: make_list("12.2(2)XB11") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(8)ZB7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(8)T10 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XN", "12.2XT")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(11)T9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(8)YY or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YK")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(13)ZC or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YL", "12.2YM", "12.2YU", "12.2YV")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(13)ZH2 or later\n'); exit(0);
}
# Affected: 12.2YP
if (check_release(version: version,
                  patched: make_list("12.2(11)YP1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YQ", "12.2YR")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)ZL or later\n'); exit(0);
}
# Affected: 12.2YS
if (check_release(version: version,
                  patched: make_list("12.2(15)YS") )) {  # the advisory says "12.2(15)YS/1.2(1)", assuming it's a typo
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2YW
if (check_release(version: version,
                  patched: make_list("12.2(8)YW2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2YX
if (check_release(version: version,
                  patched: make_list("12.2(11)YX1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2YY
if (check_release(version: version,
                  patched: make_list("12.2(8)YY3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2YZ
if (check_release(version: version,
                  patched: make_list("12.2(11)YZ2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2ZA
if (check_release(version: version,
                  patched: make_list("12.2(14)ZA2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2ZB
if (check_release(version: version,
                  patched: make_list("12.2(8)ZB7") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2ZC
if (check_release(version: version,
                  patched: make_list("12.2(13)ZC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZD")) {
 security_hole(port:0, extra: '\nNo fix is available for 12.2ZD releases. Update to a supported release\n'); exit(0);
}
# Affected: 12.2ZE
if (deprecated_version(version, "12.2ZE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(1a) or later\n'); exit(0);
}
# Affected: 12.2ZF
if (check_release(version: version,
                  patched: make_list("12.2(13)ZF1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZG")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(13)ZH2 or later\n'); exit(0);
}
# Affected: 12.2ZH
if (check_release(version: version,
                  patched: make_list("12.2(13)ZH2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2ZJ
if (check_release(version: version,
                  patched: make_list("12.2(15)ZJ1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
