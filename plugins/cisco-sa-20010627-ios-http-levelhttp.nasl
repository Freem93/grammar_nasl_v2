#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1393.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48956);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0537");
 script_bugtraq_id(2936);
 script_osvdb_id(578);
 script_xref(name:"CERT-CC", value:"CA-2001-14");
 script_name(english:"IOS HTTP Authorization Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'When the HTTP server is enabled and local authorization is used, it is
possible, under some circumstances, to bypass the authentication and
execute any command on the device. In that case, the user will be able
to exercise complete control over the device. All commands will be
executed with the highest privilege (level 15). 
All releases of Cisco IOS software, starting with release 11.3 and
later, are vulnerable. Virtually all mainstream Cisco routers and
switches running Cisco IOS software are affected by this vulnerability.

Products that are not running Cisco IOS software are not vulnerable. 
The workaround for this vulnerability is to disable HTTP server on the
router or to use Terminal Access Controller Access Control System
(TACACS+) or Radius for authentication. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010627-ios-http-level
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?faba55ec");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1393.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6a9a2877");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20010627-ios-http-level.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(287);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/06/27");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt93862");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20010627-ios-http-level");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Affected: 11.3
if (deprecated_version(version, "11.3")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(18) or later\n'); exit(0);
}
# Affected: 11.3AA
if (deprecated_version(version, "11.3AA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(9) or later\n'); exit(0);
}
# Affected: 11.3DA
if (deprecated_version(version, "11.3DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7)DA2 or later\n'); exit(0);
}
# Affected: 11.3DB
if (deprecated_version(version, "11.3DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)DB2 or later\n'); exit(0);
}
# Affected: 11.3HA
if (deprecated_version(version, "11.3HA")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(18) or later\n'); exit(0);
}
# Affected: 11.3MA
if (deprecated_version(version, "11.3MA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(9) or later\n'); exit(0);
}
# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(9) or later\n'); exit(0);
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(18) or later\n'); exit(0);
}
# Affected: 11.3XA
if (deprecated_version(version, "11.3XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(18) or later\n'); exit(0);
}
# Affected: 11.3WA4
if (deprecated_version(version, "11.3WA") && version =~ "WA4") {
 security_hole(port:0, extra: '\nUpgrade to 12.0W\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(18)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7)DA2 or later\n'); exit(0);
}
# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)DB2 or later\n'); exit(0);
}
# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1DC\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(18)S") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(16)SC") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(18)ST") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9)\n'); exit(0);
}
# Affected: 12.0(10)W5(18g)
if (version == '12.0(10)W5(18g)') {
 security_hole(port:0, extra: '\nUpdate to 12.0(18)W5(22a) or later\n'); exit(0);
}
# Affected: 12.0(14)W5(20)
if (version == '12.0(14)W5(20)') {
 security_hole(port:0, extra: '\nUpdate to 12.0(18)W5(22) or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5.4)WC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WT
if (deprecated_version(version, "12.0WT")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.0WT. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(8a)E or later\n'); exit(0);
}
# Affected: 12.0XF
if (deprecated_version(version, "12.0XF")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XH
if (deprecated_version(version, "12.0XH")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0(5)XK, 12.0(7)XK
if (version == '12.0(5)XK' || version == '12.0(7)XK') {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XL
if (deprecated_version(version, "12.0XL")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XM
if (check_release(version: version,
                  patched: make_list("12.0(4)XM1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XN
if (deprecated_version(version, "12.0XN")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XP
if (deprecated_version(version, "12.0XP")) {
 security_hole(port:0, extra: '\nUpgrade to 12.0(5.4)WC1 or later\n'); exit(0);
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(9) or later\n'); exit(0);
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 security_hole(port:0, extra: '\nUpgrade to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.0XS
if (deprecated_version(version, "12.0XS")) {
 security_hole(port:0, extra: '\nUpgrade to 12.1(8a)E or later\n'); exit(0);
}
# Affected: 12.0XU
if (deprecated_version(version, "12.0XU")) {
 security_hole(port:0, extra: '\nUpgrade to 12.0(5.4)WC1 or later\n'); exit(0);
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 security_hole(port:0, extra: '\nUpgrade to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(9)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(9)AA") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DA
if (check_release(version: version,
                  patched: make_list("12.1(7)DA") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DB
if (deprecated_version(version, "12.1DB")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1DB. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1DC
if (deprecated_version(version, "12.1DC")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1DC. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(6.5)EC3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EX
if (deprecated_version(version, "12.1EX")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(8a)E or later\n'); exit(0);
}
# Affected: 12.1EY
if (check_release(version: version,
                  patched: make_list("12.1(6)EY") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1XB. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(9)AA or later\n'); exit(0);
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1XE. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(5)XG5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)YB4 or later\n'); exit(0);
}
# Affected: 12.1XK
if (deprecated_version(version, "12.1XK")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1XK. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(4)XM4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XP
if (check_release(version: version,
                  patched: make_list("12.1(3)XP4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(1b) or later\n'); exit(0);
}
# Affected: 12.1XR
if (check_release(version: version,
                  patched: make_list("12.1(5)XR2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XS
if (check_release(version: version,
                  patched: make_list("12.1(5)XS2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XT
if (check_release(version: version,
                  patched: make_list("12.1(3)XT3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XU
if (check_release(version: version,
                  patched: make_list("12.1(5)XU1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XW
if (deprecated_version(version, "12.1XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.2DD\n'); exit(0);
}
# Affected: 12.1XX
if (deprecated_version(version, "12.1XX")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(6)EZ or later\n'); exit(0);
}
# Affected: 12.1XY
if (check_release(version: version,
                  patched: make_list("12.1(5)XY6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XZ
if (check_release(version: version,
                  patched: make_list("12.1(5)XZ4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YA
if (deprecated_version(version, "12.1YA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(2)XB or later\n'); exit(0);
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YD
if (check_release(version: version,
                  patched: make_list("12.1(5)YD2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1b)", "12.2(1c)", "12.2(1.1)", "12.2(3)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2.2)T") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XA
if (check_release(version: version,
                  patched: make_list("12.2(2)XA") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(1)XD1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(1)XH") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(1)XQ") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
