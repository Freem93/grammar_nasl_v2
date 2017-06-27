#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080436587.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48985);
 script_version("$Revision: 1.13 $");
 script_cve_id(
  "CVE-2004-0790",
  "CVE-2004-0791",
  "CVE-2004-1060",
  "CVE-2005-0065",
  "CVE-2005-0066",
  "CVE-2005-0067",
  "CVE-2005-0068"
 );
 script_bugtraq_id(13124);
 script_osvdb_id(
   15457,
   15618,
   15619,
   15620,
   15621,
   15622,
   15623
 );
 script_xref(name:"CERT", value:"222750");
 script_name(english:"Crafted ICMP Messages Can Cause Denial of Service - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'A document that describes how the Internet Control Message Protocol
(ICMP) could be used to perform a number of Denial of Service (DoS)
attacks against the Transmission Control Protocol (TCP) has been made
publicly available. This document has been published through the
Internet Engineering Task Force (IETF) Internet Draft process, and is
entitled "ICMP Attacks Against TCP"
(draft-gont-tcpm-icmp-attacks-03.txt ).
These attacks, which only affect sessions terminating or originating on
a device itself, can be of three types:
Successful attacks may cause connection resets or reduction of
throughput in existing connections, depending on the attack type.
Multiple Cisco products are affected by the attacks described in this
Internet draft.
Cisco has made free software available to address these
vulnerabilities. In some cases there are workarounds available to
mitigate the effects of the vulnerability.
');
 script_set_attribute(attribute:"see_also", value: "http://www.gont.com.ar/drafts/icmp-attacks-against-tcp.html");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20050412-icmp
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?63625845");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080436587.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d156c2da");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050412-icmp."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/11/23 14:38:40 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCed78149");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef43691");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef44699");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef45332");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef46728");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef54204");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef54206");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef54947");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef57566");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef60659");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef61610");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh04183");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh20083");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh45454");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh59823");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh62307");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh63449");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeh65337");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa52807");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa59600");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa60692");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa61864");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20050412-icmp");
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

# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(28c)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(12)DA8 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.0DC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(27)S5", "12.0(28)S3", "12.0(30)S1", "12.0(31)S"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SL")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(31)S or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SP")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(31)S or later\n'); exit(0);
}
if (deprecated_version(version, "12.0ST")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(31)S or later\n'); exit(0);
}
if (deprecated_version(version, "12.0SX")) {
 security_warning(port:0, extra: '\nNo fixes are planned for 12.0SX releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.0SZ")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(31)S or later\n'); exit(0);
}
if (deprecated_version(version, "12.0T")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
# Affected: 12.0W5
if ("W5" >< version &&
    check_release(version: version,
                  patched: make_list("12.0(25)W5(27c)", "12.0(28)W5(31a)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC12") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(26)E1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XN")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XS")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(26)E1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.0XV")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(27) or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(27)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AX")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(25)EY or later\n'); exit(0);
}
if (deprecated_version(version, "12.1AZ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(22)EA4 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(12)DA8 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.1DC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(22)E6", "12.1(23)E3", "12.1(26)E1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(22)EA4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EB")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.1EB releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.1EC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
# Affected: 12.1EO
if (check_release(version: version,
                  patched: make_list("12.1(19)EO4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EU")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(20)EU or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EV")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.1EV releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.1EW")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(18)EW3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EX")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(26)E1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1EY")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(26)E1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1T")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(26)E1 or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(28) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XP")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XT")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XU")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1XV")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YA")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YC")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YE")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YF")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YH")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YI")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.1YJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(22)EA4 or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(28)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2B")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(15)BC2f") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BW")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BY")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2BZ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(7)XI5 or later\n'); exit(0);
}
# Affected: 12.2CX
if (deprecated_version(version, "12.2CX")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
# Affected: 12.2CY
if (deprecated_version(version, "12.2CY")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
if (deprecated_version(version, "12.2CZ")) {
 security_warning(port:0, extra: '\nNo fix is planned for 12.2CZ releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(12)DA8") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2DX")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.2EU
if (check_release(version: version,
                  patched: make_list("12.2(20)EU"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(25)EWA") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2EX")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(25)SEB or later\n'); exit(0);
}
# Affected: 12.2EY
if (check_release(version: version,
                  patched: make_list("12.2(25)EY") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2JA")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(4)JA or later\n'); exit(0);
}
if (deprecated_version(version, "12.2JK")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2JK releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2MB")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2MB releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2MC")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S13", "12.2(18)S8", "12.2(20)S7", "12.2(25)S3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SE
if (check_release(version: version,
                  patched: make_list("12.2(25)SEB"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2SO
if (check_release(version: version,
                  patched: make_list("12.2(18)SO1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SU")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2SU releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2SV")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(25)S3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SW")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2SU releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2SX")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(17d)SXB7 or later\n'); exit(0);
}
# Affected: 12.2SXA and 12.2SXB
if (("SXA" >< version || "SXB" >< version) &&
    check_release(version: version,
                  patched: make_list("12.2(17d)SXB7") )) {
 security_warning(port:0, extra: '\nUpdate to 12.2(17d)SXB7 or later\n'); exit(0);
}
# Affected: 12.2SXD
if ("SXD" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXD4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SY")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(17d)SXB7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2SZ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(20)S7 or later\n'); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(15)T15") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(15)BC2f or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XN")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(4)JA or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XT")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XU")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2XW")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA9") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YC")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YE")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(25)S3 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YF")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YG")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YH")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YK")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YL")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YM")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YO")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(17d)SXB7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YR")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YT")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YU")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YV")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YW")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YX")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2YX releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.2YY")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2YZ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(20)S7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(17d)SXB7 or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZC")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZE")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(13) or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZF")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZG")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.2ZH
if (check_release(version: version,
                  patched: make_list("12.2(13)ZH6") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZK")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.2ZL
if (check_release(version: version,
                  patched: make_list("12.2(15)ZL2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZN")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.2ZP")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.2ZP releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(3h)", "12.3(5e)", "12.3(6e)", "12.3(9d)", "12.3(10c)", "12.3(12b)", "12.3(13a)", "12.3(13)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3B")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(9a)BC2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3BW")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(7)T8 or later\n'); exit(0);
}
# Affected: 12.3JA
if (check_release(version: version,
                  patched: make_list("12.3(4)JA"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(7)T8", "12.3(8)T7", "12.3(11)T4", "12.3(14)T"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.3XC
if (check_release(version: version,
                  patched: make_list("12.3(2)XC3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XG")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3XG releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XJ")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3XJ releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XS")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XT")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(4)JA or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XU")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3XU releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3XW")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(11)YF2 or later\n'); exit(0);
}
if (deprecated_version(version, "12.3XX")) {
 security_warning(port:0, extra: '\nUpdate to 12.3(14)T or later\n'); exit(0);
}
# Affected: 12.3XY
if (check_release(version: version,
                  patched: make_list("12.3(8)XY4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YA")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3YA releases. Upgrade to a supported release\n'); exit(0);
}
if (deprecated_version(version, "12.3YD")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3YD releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.3YF
if (check_release(version: version,
                  patched: make_list("12.3(11)YF2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YG
if (check_release(version: version,
                  patched: make_list("12.3(8)YG1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YH")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3YH releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.3YI
if (check_release(version: version,
                  patched: make_list("12.3(8)YI"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
if (deprecated_version(version, "12.3YJ")) {
 security_warning(port:0, extra: '\nNo fixes are available for 12.3YJ releases. Upgrade to a supported release\n'); exit(0);
}
# Affected: 12.3YK
if (check_release(version: version,
                  patched: make_list("12.3(11)YK"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: TCPv6
if (check_release(version: version,
                  patched: make_list("12.3(11)YK") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YN
if (check_release(version: version,
                  patched: make_list("12.3(11)YN"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.3YQ
if (check_release(version: version,
                  patched: make_list("12.3(14)YQ"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
