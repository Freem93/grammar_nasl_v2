#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13c3.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48949);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0380");
 script_bugtraq_id(1154);
 script_osvdb_id(1302);
 script_xref(name:"CERT", value:"24346");
 script_name(english:"Cisco IOS HTTP Server Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'A defect in multiple releases of Cisco IOS software will cause a Cisco
router or switch to halt and reload if the IOS HTTP service is enabled
and browsing to "http://<router-ip>/%%" is attempted. This defect can
be exploited to produce a denial of service (DoS) attack. This defect
has been discussed on public mailing lists and should be considered
public information. 
The vulnerability, identified as Cisco bug ID CSCdr36952, affects
virtually all mainstream Cisco routers and switches running Cisco IOS
software releases 11.1 through 12.1, inclusive. The vulnerability has
been corrected and Cisco is making fixed releases available to replace
all affected IOS releases. Customers are urged to upgrade to releases
that are not vulnerable to this defect as shown in detail below. 
The vulnerability can be mitigated by disabling the IOS HTTP server,
using an access-list on an interface in the path to the router to
prevent unauthorized network connections to the HTTP server, or
applying an access-class option directly to the HTTP server itself. The
IOS HTTP server is enabled by default only on Cisco 1003, 1004, and
1005 routers that are not configured. In all other cases, the IOS http
server must be explicitly enabled in order to exploit this defect. 
');
 script_set_attribute(attribute:"see_also", value: "http://seclists.org/bugtraq/2000/Apr/250");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20000514-ios-http-server
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?27e432a9");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13c3.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ae78d855");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20000514-ios-http-server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/10/05 20:44:33 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr36952");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20000514-ios-http-server");
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

# Affected: 11.1
if (deprecated_version(version, "11.1")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 11.1. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.1CA
if (check_release(version: version,
                  patched: make_list("11.1(33.2)CA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(33)CC1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(22.2)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2BC
if (check_release(version: version,
                  patched: make_list("11.2(22.1)BC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(22.2)P"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3DA
if (check_release(version: version,
                  patched: make_list("11.3(1)DA9") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(11.1)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (check_release(version: version,
                  patched: make_list("12.0(8)DA5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(10)S1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(10.6)SC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SL
if (check_release(version: version,
                  patched: make_list("12.0(9)SL1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(9)ST1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0W5 (should cover all models)
if (check_release(version: version,
                  patched: make_list("12.0(5)W5(13d)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5.4)WC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(1b)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(1)AA2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DA
if (check_release(version: version,
                  patched: make_list("12.1(1)DA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(1)DB"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(1)DC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(1)E2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(2)EC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(2)T2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XZ***
if (deprecated_version(version, "12.1XZ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(1)XA3 or later\n'); exit(0);
}
# Affected: 12.1XD
if (check_release(version: version,
                  patched: make_list("12.1(1)XD"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XE
if (check_release(version: version,
                  patched: make_list("12.1(1)XE"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
