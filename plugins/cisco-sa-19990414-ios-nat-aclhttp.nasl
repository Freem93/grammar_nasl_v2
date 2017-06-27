#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13a8.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48947);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-1999-0445");
 script_bugtraq_id(706);
 script_osvdb_id(1104);
 script_name(english:"Cisco IOS Software Input Access List Leakage with NAT - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'A group of related software bugs (bug IDs given under "Software
Versions and Fixes") create an undesired interaction between network
address translation (NAT) and input access list processing in certain
Cisco routers running 12.0-based versions of Cisco IOS software
(including 12.0, 12.0S, and 12.0T, in all versions up to, but not
including, 12.0(4), 12(4)S, and 12.0(4)T, as well as other 12.0
releases). Non-12.0 releases are not affected. 
This may cause input access list filters to "leak" packets in certain
NAT configurations, creating a security exposure. Configurations
without NAT are not affected. 
The failure does not happen at all times, and is less likely under
laboratory conditions than in installed networks. This may cause
administrators to believe that filtering is working when it is not. 
Software fixes are being created for this vulnerability, but are not
yet available for all software versions (see the section on "Software
Versions and Fixes"). This notice is being released before fixed
software is universally available in order to enable affected Cisco
customers to take immediate steps to protect themselves against this
vulnerability. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19990414-ios-nat-acl
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?daf3883e");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13a8.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?48c1d7b8");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-19990414-ios-nat-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/14");
 script_set_attribute(attribute:"patch_publication_date", value: "1999/04/14");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdk79747");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm22299");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm22451");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm22569");
 script_xref(name:"CISCO-SA", value: "cisco-sa-19990414-ios-nat-acl");
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
                  patched: make_list("12.0(3b)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(4)S"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(3)T2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0(1)XA3, 12.0(2)XC, 12.0(2)XD
if (
  version == '12.0(1)XA3' ||
  version == '12.0(2)XC' ||
  version == '12.0(2)XD'
) {
 security_warning(port:0, extra: '\nUpdate to 12.0(3)T2 or later\n'); exit(0);
}
# Affected: 12.0XE
if (check_release(version: version,
                  patched: make_list("12.0(2)XE3"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0(2)XG
if (version == '12.0(2)XG') {
 security_warning(port:0, extra: '\nUpdate to 12.0(4)T or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
