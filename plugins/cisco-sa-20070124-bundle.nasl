#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00807cb14c.shtml
#
# Disabled on 2012/10/18. replaced by:
# cisco-sa-20070124-crafted-ip-option.nasl
# cisco-sa-20070124-crafted-tcp.nasl
# cisco-sa-20070124-IOS-IPv6.nasl

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48995);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2007-0479", "CVE-2007-0480", "CVE-2007-0481");
 script_bugtraq_id(22208, 22210, 22211);
 script_osvdb_id(32091, 32092, 32093);
 script_xref(name:"CERT", value:"217912");
 script_xref(name:"CERT", value:"274760");
 script_xref(name:"CERT", value:"341288");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef67682");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd40334");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070124-bundle");
 script_name(english:"Combined IOS Table for January 24, 2007 Security Advisories (deprecated)");
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
'On January 24 2007, Cisco released three security advisories
for vulnerabilities in the TCP/IP implementation of IOS.  Exploitation
of these vulnerabilities could result in a denial of service or
execution of arbitrary code.  This plugin checks if the appropriate
fix for all three advisories has been installed.

This plugin has been replaced by plugins that check for the three
individual adivsories covered by this bundle - plugins 48996,
48997, and 48998.'
 );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070124-crafted-ip-option
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?cdec28c3");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070124-crafted-tcp
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7468b1c7");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070124-IOS-IPv6
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ffa2c05c");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00807cb14c.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?89eaa57e");
 script_set_attribute(attribute:"solution", value:
"n/a"
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/01/24");
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

exit(0, 'This plugin is deprecated.  Use plugins 48996, 48997, and 48998 instead.');

include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (deprecated_version(version, "12.0")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(10)DA5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(32)S4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SL")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(32)S4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SP")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(32)S4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0ST")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(32)S4 or later\n'); exit(0);
}
# Affected: 12.0SX
if (check_release(version: version,
                  patched: make_list("12.0(25)SX11") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Note: 12.0(30)SX is the only 12.0SX release vulnerable to CSCef67682 and CSCsd40334; contact TAC
if (version == "12.0(30)SX") {
 security_hole(port:0, extra: '\n12.0(30)SX is vulnerable to CSCef67682 and CSCsd40334. Contact Cisco for more information\n'); exit(0);
}
# Affected: 12.0SY
if (check_release(version: version,
                  patched: make_list("12.0(32)SY"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(32)S4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0T")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
# Affected: 12.0W
if ("W5" >< version &&
    check_release(version: version,
                  patched: make_list("12.0(28)W5(32b)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC15") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0WT")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.0WT releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.0XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XN")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(5)WC15 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)EY4 (c3750-ME) / 12.2(35)SE (c2970, 3750) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AY")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA8 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA8 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1CX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(10)DA5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(26)E7", "12.1(27b)E1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(22)EA8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EB")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.1EB releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.1EC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
# Affected: 12.1EO
if (check_release(version: version,
                  patched: make_list("12.1(19)EO6", "12.1(20)EO3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EU")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)EWA6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EV")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(27)SV4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EW")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)EWA6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EX")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EY")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1T")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(26)E7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XP")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(37) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YI")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(22)EA8 or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(37)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2B")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(7)XI9 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CZ")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2CZ releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(10)DA5", "12.2(12)DA10") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DX")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2EU")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)EWA6 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2EW")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)EWA6 or later\n'); exit(0);
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(25)EWA6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EX
if (check_release(version: version,
                  patched: make_list("12.2(25)EX1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EY
if (check_release(version: version,
                  patched: make_list("12.2(25)EY4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2EZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2FX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2FY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2IXA")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2IXA releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2IXB")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2IXB releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2IXC")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2IXC releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2JA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(8)JA2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2JK")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(4)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2MB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SW8 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2MC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(25)S12") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SB
if (check_release(version: version,
                  patched: make_list("12.2(28)SB2", "12.2(31)SB"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SBC
if ("SBC" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(27)SBC5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SE
# avoid flagging releases like 12.2SEA, 12.2SEB, etc
if (version !~ "SE[A-Z]" &&
    check_release(version: version,
                  patched: make_list("12.2(35)SE"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SEA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SEB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SEC")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SED")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)SEE1 or later\n'); exit(0);
}
# Affected: 12.2SEE
if ("SEE" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(25)SEE1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SEF
if ("SEF" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(25)SEF1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SG")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2SG releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.2SO
if (check_release(version: version,
                  patched: make_list("12.2(18)SO7") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SU")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
# Affected: 12.2SV
if (check_release(version: version,
                  patched: make_list("12.2(27)SV4", "12.2(28)SV1", "12.2(29)SV1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SW
if (check_release(version: version,
                  patched: make_list("12.2(25)SW8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SX")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(18)SXD7a or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SXA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(18)SXD7a or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SXB")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(18)SXD7a or later\n'); exit(0);
}
# Affected: 12.2SXD
if (check_release(version: version,
                  patched: make_list("12.2(18)SXD7a") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SXE
if (check_release(version: version,
                  patched: make_list("12.2(18)SXE6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SXF
if (check_release(version: version,
                  patched: make_list("12.2(18)SXF5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SY")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(18)SXD7a or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S12 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2T")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2TPC")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2TPC releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(17b)BC3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YA")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YE")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S12 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YG")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YK")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YL")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YM")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YP")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YR")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YT")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YU")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YV")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YX")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YY")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(25)S12 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZA")) {
 security_hole(port:0, extra: '\nUpdate to 12.2(18)SXD7a or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZC")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZD")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2ZD releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2ZE")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(19) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZG")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2ZG releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2ZH")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2ZH releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2ZJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZL")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.2ZL releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2ZN")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(4)T13 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZP")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(19)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3B")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(17b)BC3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3BW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
# Affected: 12.3JA
if (check_release(version: version,
                  patched: make_list("12.3(8)JA2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3JK
if (check_release(version: version,
                  patched: make_list("12.3(2)JK2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3JX
if (check_release(version: version,
                  patched: make_list("12.3(7)JX6", "12.3(11)JX"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(4)T13", "12.3(11)T11") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3TPC")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3TPC releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XA")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3XA releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XC")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3XC releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XE")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3XE releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XG")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3XG releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XH")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(11)T11 or later\n'); exit(0);
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI8a", "12.3(7)XI9"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)YX2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XR")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3XR releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XW")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)YX2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XX")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XY")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(8) or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YA")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3YA releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3YD")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YF")) {
 security_hole(port:0, extra: '\nUpdate to 12.3(14)YX2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YG")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YH")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YI")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(2)T5 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(6)T3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YK")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(4)T4 or later\n'); exit(0);
}
# Affected: 12.3YM
if (check_release(version: version,
                  patched: make_list("12.3(14)YM8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(6)T3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YS")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(4)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YT")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(4)T4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YU")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.3YU releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.3YX
if (check_release(version: version,
                  patched: make_list("12.3(14)YX2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YZ
if (check_release(version: version,
                  patched: make_list("12.3(11)YZ1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4
if (check_release(version: version,
                  patched: make_list("12.4(3e)", "12.4(7b)", "12.4(8)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4MR
if (check_release(version: version,
                  patched: make_list("12.4(6)MR1", "12.4(9)MR"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4T
if (check_release(version: version,
                  patched: make_list("12.4(2)T5", "12.4(4)T4", "12.4(6)T3", "12.4(9)T") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.4XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.4(6)T3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.4XB")) {
 security_hole(port:0, extra: '\nNo fixes are available for 12.4XB releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.4XC
if (check_release(version: version,
                  patched: make_list("12.4(4)XC5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.4XD
if (check_release(version: version,
                  patched: make_list("12.4(4)XD2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
