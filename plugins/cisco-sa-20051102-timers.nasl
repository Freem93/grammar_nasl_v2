#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008055ef31.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48989);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2005-3481");
 script_bugtraq_id(15275);
 script_osvdb_id(20455);
 script_name(english:"IOS Heap-based Overflow Vulnerability in System Timers - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'The Cisco Internetwork Operating System (IOS) may permit arbitrary
code execution after exploitation of a heap-based buffer overflow
vulnerability. Cisco has included additional integrity checks in its
software, that are intended to reduce the likelihood of arbitrary
code execution.

This is not a specific vulnerability, but a design weakness that
increases the likelihood of exploiting other vulnerabilities.'
 );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20051102-timers
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c22defc9");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008055ef31.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?07276474");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20051102-timers."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/11/02");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCei61732");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20051102-timers");
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

# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(28d)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(12)DA9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(28)S5", "12.0(30)S4", "12.0(31)S1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SL")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(31)S1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SP")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(31)S1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0ST")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(31)S1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SX")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.0SX release. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.0SZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(31)S1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0T")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
# Affected: 12.0W5
# The advisory displays the versions strangely, e.g., 12.0(25)W5-27d instead of 12.0(25)W5(27d).
# we'll reformat the version to the format that we expect the IOS device to report the release in
if ("W5" >< version && # avoid flagging versions like W5
    check_release(version: version,
                  patched: make_list("12.0(25)W5(27d)", "12.0(28)W5(30b)", "12.0(28)W5(32a)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC13") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XN")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(27b) or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(27b)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AX")) {
 security_hole(port:0, extra: '\n12.1AX releases are vulnerable. Migrate to the appropriate release (refer to the advisory for more details)\n'); exit(0);
}
if (deprecated_version(version, "12.1AY")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA4a or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA4a or later\n'); exit(0);
}
if (deprecated_version(version, "12.1CX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(12)DA9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8b)E20", "12.1(13)E17", "12.1(23)E4", "12.1(26)E3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(22)EA4a", "12.1(22)EA6"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EB
if (check_release(version: version,
                  patched: make_list("12.1(26)EB1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
# Affected: 12.1EO
if (check_release(version: version,
                  patched: make_list("12.1(20)EO3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EU")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(20)EU2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EV")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(26)SV1 or later\n'); exit(0);
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(12c)EW4", "12.1(13)EW4", "12.1(19)EW3", "12.1(20)EW4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EX")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EY")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1T")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XP")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(31) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YI")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA4a or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(12m)", "12.2(17f)", "12.2(23f)", "12.2(26b)", "12.2(27b)", "12.2(28c)", "12.2(29a)", "12.2(31)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2B")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(15)BC2i") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(7)XI7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(7)XI7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
# Affected: 12.2CZ
if (check_release(version: version,
                  patched: make_list("12.2(15)CZ3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(10)DA4", "12.2(12)DA9") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.2EU
if (check_release(version: version,
                  patched: make_list("12.2(20)EU2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW5", "12.2(20)EW3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(20)EWA3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EX
if (check_release(version: version,
                  patched: make_list("12.2(25)EX"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EY
if (check_release(version: version,
                  patched: make_list("12.2(25)EY3"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2EZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEC2 / 12.2(25)SED or later\n'); exit(0);
}
# Affected: 12.2FX
if (check_release(version: version,
                  patched: make_list("12.2(25)FX"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2FY
if (check_release(version: version,
                  patched: make_list("12.2(25)FY"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2JA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(7)JA1 or later\n'); exit(0);
}
# Affected: 12.2JK
if (check_release(version: version,
                  patched: make_list("12.2(15)JK5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB13c") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2MC
if (check_release(version: version,
                  patched: make_list("12.2(15)MC2e") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S15", "12.2(18)S10", "12.2(20)S9", "12.2(25)S6", "12.2(30)S1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SBC
if ("SBC" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(27)SBC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SE
if (check_release(version: version,
                  patched: make_list("12.2(25)SEB4"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if ("SEC" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(25)SEC2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SG
if (check_release(version: version,
                  patched: make_list("12.2(25)SG"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SO
if (check_release(version: version,
                  patched: make_list("12.2(18)SO4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.2SV
if (check_release(version: version,
                  patched: make_list("12.2(26)SV1", "12.2(27)SV1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SW
if (check_release(version: version,
                  patched: make_list("12.2(25)SW4"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17d)SXB10 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SXA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17d)SXB10 or later\n'); exit(0);
}
# Affected: 12.2SXB
if ("SXB" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(17d)SXB10") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SXD
if ("SXD" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXD6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SXE
if ("SXE" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXE3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SXF
if ("SXF" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXF"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17d)SXB10 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S6 or later\n'); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(15)T17") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2TPC
if (check_release(version: version,
                  patched: make_list("12.2(8)TPC10a") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(15)BC2i or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
# 12.2(2)XR and 12.2(4)XR vulnerable, migrate to 12.3(16) or later
if (version == "12.2(2)XR" || version == "12.2(4)XR") {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
# 12.2(15)XR vulnerable; migrate to 12.3(7)JA1
if (version == "12.2(15)XR") {
 security_hole(port:0, extra: '\nUpdate to 12.3(7)JA1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA11") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YE")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YK")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YO")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17d)SXB10 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YP")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YR")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.2YS
if (check_release(version: version,
                  patched: make_list("12.2(15)YS"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(17d)SXB10 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.2ZD
if (check_release(version: version,
                  patched: make_list("12.2(13)ZD4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(16) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(8)YG3 (SOHO9x) / 12.3(2)XA5 (c83x) or later\n'); exit(0);
}
# Affected: 12.2ZH
if (check_release(version: version,
                  patched: make_list("12.2(13)ZH8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)XK4 (c17xx) / 12.4(3a) (c3200) / 12.3(7)XR6 (ICS7750) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZP")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(3i)", "12.3(5f)", "12.3(6f)", "12.3(9e)", "12.3(10e)", "12.3(12e)", "12.3(13b)", "12.3(15b)", "12.3(16)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3B")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(9a)BC7", "12.3(13a)BC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3BW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3JA
if (check_release(version: version,
                  patched: make_list("12.3(2)JA5", "12.3(4)JA1", "12.3(7)JA1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3JK
if (check_release(version: version,
                  patched: make_list("12.3(2)JK1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3JX
if (check_release(version: version,
                  patched: make_list("12.3(7)JX") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(7)T12", "12.3(8)T11", "12.3(11)T8", "12.3(14)T4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3TPC
if (check_release(version: version,
                  patched: make_list("12.3(4)TPC11a") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3XA
if (check_release(version: version,
                  patched: make_list("12.3(2)XA5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3XC
if (check_release(version: version,
                  patched: make_list("12.3(2)XC4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3XE
if (check_release(version: version,
                  patched: make_list("12.3(4)XE4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3XG
if (check_release(version: version,
                  patched: make_list("12.3(4)XG5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI7") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)YF4 or later\n'); exit(0);
}
# Affected: 12.3XK
if (check_release(version: version,
                  patched: make_list("12.3(4)XK4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(3a) or later\n'); exit(0);
}
# Affected: 12.3XR
if (check_release(version: version,
                  patched: make_list("12.3(7)XR6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(3a) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)YF4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XX")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(3a) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YA")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(3a) (C828) / 12.3(8)YG3 (SOHO9x, C83x) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T1 or later\n'); exit(0);
}
# Affected: 12.3YF
if (check_release(version: version,
                  patched: make_list("12.3(11)YF4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YG
if (check_release(version: version,
                  patched: make_list("12.3(8)YG3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(8)YI3 or later\n'); exit(0);
}
# Affected: 12.3YI
if (check_release(version: version,
                  patched: make_list("12.3(8)YI3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YJ
if (deprecated_version(version, "12.3YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)YQ3 or later\n'); exit(0);
}
# Affected: 12.3YK
if (check_release(version: version,
                  patched: make_list("12.3(11)YK2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YQ
if (check_release(version: version,
                  patched: make_list("12.3(14)YQ3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YS
if (check_release(version: version,
                  patched: make_list("12.3(11)YS1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YT
if (check_release(version: version,
                  patched: make_list("12.3(14)YT1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YU
if (check_release(version: version,
                  patched: make_list("12.3(14)YU1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4
if (check_release(version: version,
                  patched: make_list("12.4(1b)", "12.4(3a)", "12.4(5)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4MR
if (check_release(version: version,
                  patched: make_list("12.4(2)MR1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4T
if (check_release(version: version,
                  patched: make_list("12.4(2)T1", "12.4(4)T"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4XA
if (check_release(version: version,
                  patched: make_list("12.4(2)XA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4XB
if (check_release(version: version,
                  patched: make_list("12.4(2)XB"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
