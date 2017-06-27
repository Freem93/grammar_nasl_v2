#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b2.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48955);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0750");
 script_bugtraq_id(2804);
 script_osvdb_id(800);
 script_xref(name:"CERT", value:"178024");
 script_name(english:"IOS Reload after Scanning Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Security Scanning software can cause a memory error in Cisco IOS
Software that will cause a reload to occur. This vulnerability affects
only Cisco IOS software version 12.1(2)T and 12.1(3)T, and limited
deployment releases based on those versions. 
Customers using the affected Cisco IOS software releases are urged to
upgrade as soon as possible to later versions that are not vulnerable
to this defect. Vulnerable products and releases are listed in detail
below. 
The security scanner makes TCP connection attempts to various ports,
looking for open ports to further investigate known vulnerabilities
with those services associated with certain ports. However, a side
effect of the tests exposes the defect described in this security
advisory, and the router will reload unexpectedly as soon as it
receives a request to review or write the configuration file.
This defect is documented as Cisco Bug ID CSCds07326.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010524-ios-tcp-scanner-reload
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?3794b3d8");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b2.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?8cfed854");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20010524-ios-tcp-scanner-reload.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/05/24");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCds07326");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20010524-ios-tcp-scanner-reload");
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

# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(4)DB") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(4)DC") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(4.3)T"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XF
if (deprecated_version(version, "12.1XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XG
if (deprecated_version(version, "12.1XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.2T or later\n'); exit(0);
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2T or later\n'); exit(0);
}
# Affected: 12.1XK
if (deprecated_version(version, "12.1XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(1) or later\n'); exit(0);
}
# Affected: 12.1XP
if (deprecated_version(version, "12.1XP")) {
 security_warning(port:0, extra: '\nUpdate to 12.2T or later\n'); exit(0);
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2T or later\n'); exit(0);
}
# Affected: 12.1XS
if (check_release(version: version,
                  patched: make_list("12.1(5)XS") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XT
if (deprecated_version(version, "12.1XT")) {
 security_warning(port:0, extra: '\nUpdate to 12.2T or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
