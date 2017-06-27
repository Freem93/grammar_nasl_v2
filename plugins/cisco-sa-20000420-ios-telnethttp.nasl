#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1699.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48948);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0268");
 script_bugtraq_id(1123);
 script_osvdb_id(1289);
 script_name(english:"Cisco IOS Software TELNET Option Handling Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'A defect in multiple Cisco IOS software versions will cause a Cisco
router to reload unexpectedly when the router is tested for security
vulnerabilities by security scanning software programs. The defect can
be exploited repeatedly to produce a consistent denial of service (DoS)
attack. 
Customers using the affected Cisco IOS software releases are urged to
upgrade as soon as possible to later versions that are not vulnerable
to this defect. Vulnerable products and releases are listed in detail
below. 
The security scanner is testing for the presence of two specific
vulnerabilities that affect certain UNIX-based systems. The
vulnerabilities are unrelated to Cisco IOS software and Cisco IOS
software is not directly at risk from them. However, a side-effect of
the tests exposes the defect described in this security advisory, and
the router will reload unexpectedly as soon as it receives any
subsequent traffic. 
This defect is documented as Cisco Bug ID CSCdm70743. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20000420-ios-telnet
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?bad63371");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1699.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d9a6451a");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20000420-ios-telnet.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/04/20");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm70743");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20000420-ios-telnet");
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

# Affected: 11.3AA
if (check_release(version: version,
                  patched: make_list("11.3(11a)AA"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(7.1)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(6.6)S"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(6.6)SC1"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(6.5)T3"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0W
if (check_release(version: version,
                  patched: make_list("12.0(6.5)W5(16.0.9)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XE
if (check_release(version: version,
                  patched: make_list("12.0(7)XE1"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XJ
if (check_release(version: version,
                  patched: make_list("12.0(4)XJ4"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
