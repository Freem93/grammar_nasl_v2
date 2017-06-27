#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13a7.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48946);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0063");
 script_bugtraq_id(675);
 script_osvdb_id(1089);
 script_name(english:"Cisco IOS Syslog Crash - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Certain versions of Cisco IOS software may crash or hang when they
receive invalid user datagram protocol (UDP) packets sent to their
"syslog" ports (port 514). At least one commonly-used Internet scanning
tool generates packets which can cause such crashes and hangs. This
fact has been announced on public Internet mailing lists which are
widely read both by security professionals and by security "crackers",
and should be considered public information. 
This vulnerability affects devices running Cisco IOS software version
11.3AA, version 11.3DB, or any 12.0-based version (including 12.0
mainline, 12.0S, 12.0T, and any other regular released version whose
number starts with "12.0"). The vulnerability has been corrected in
certain special releases, and will be corrected in maintenance and
interim releases which will be issued in the future; see the section on
"Software Versions and Fixes" for details on which versions are
affected, and on which versions are, or will be, fixed. Cisco intends
to provide fixes for all affected IOS variants. 
There is a configuration workaround for this vulnerability. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19990111-ios-syslog
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?bc115c1e");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13a7.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?9ed084ac");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-19990111-ios-syslog.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/11");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdk77426");
 script_xref(name:"CISCO-SA", value: "cisco-sa-19990111-ios-syslog");
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

# Affected: 11.3AA
if (check_release(version: version,
                  patched: make_list("11.3(7)AA2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3DB
if (check_release(version: version,
                  patched: make_list("11.3(7)DB2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(2.4)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(2.4)T"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(2)S"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DB
if (check_release(version: version,
                  patched: make_list("12.0(2)DB"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0(1)W
if (version == '12.0(1)W') {
 security_warning(port:0, extra: '\nUpdate to 12.0(1)W5(5.15) or later\n'); exit(0);
}
# Affected: 12.0(1)XA3
if (version == '12.0(1)XA3') {
 security_warning(port:0, extra: '\nUpdate to 12.0(2a)T1 or later\n'); exit(0);
}
# Affected: 12.0(1)XB
if (version == '12.0(1)XB') {
 security_warning(port:0, extra: '\nUpdate to 12.0(1)XB1 or later\n'); exit(0);
}
# Affected: 12.0(2)XC
if (version == '12.0(2)XC') {
 security_warning(port:0, extra: '\nUpdate to 12.0(2)XC1 or later\n'); exit(0);
}
# Affected: 12.0(2)XD
if (version == '12.0(2)XD') {
 security_warning(port:0, extra: '\nUpdate to 12.0(2)XD1 or later\n'); exit(0);
}
# Affected: 12.0(1)XE
if (version == '12.0(1)XE') {
 security_warning(port:0, extra: '\nUpdate to 12.0(2)XE or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
