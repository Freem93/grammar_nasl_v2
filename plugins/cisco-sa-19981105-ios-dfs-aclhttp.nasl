#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b139b.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48945);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-1999-1464", "CVE-1999-1465");
 script_osvdb_id(8800, 8805);
 script_xref(name:"CERT-CC", value:"CA-1998-13");
 script_name(english:"Cisco IOS DFS Access List Leakage - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Errors in certain Cisco IOS software versions for certain routers can
cause IP datagrams to be output to network interfaces even though
access lists have been applied to filter those datagrams. This applies
to routers from the Cisco 7xxx family only, and only when those routers
have been configured for distributed fast switching (DFS). 
There are two independent vulnerabilities, which have been given Cisco
bug IDs CSCdk35564 and CSCdk43862. Each vulnerability affects only a
specialized subset of DFS configurations. Affected configurations are
not believed to be extremely common, but neither are they extremely
rare. More details of affected configurations are in the "Who is
Affected" section of this document. 
These vulnerabilities may permit users to send packets to parts of the
customer\'s network for which they are not authorized. This may permit
unauthorized access or other attacks on customer computer systems or
data. Cisco does not know of any incidents in which these
vulnerabilities have actually been exploited by attackers. 
Neither vulnerability affects any Cisco product other than routers in
the 70xx or 75xx series. Of 70xx routers, only routers with the
optional route-switch processor (RSP) card are affected. Additional
configuration conditions apply. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19981105-ios-dfs-acl
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?bb5faf44");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b139b.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c410b1d6");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-19981105-ios-dfs-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/11/05");
 script_set_attribute(attribute:"patch_publication_date", value: "1998/11/05");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdk35564");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdk43696");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdk43862");
 script_xref(name:"CISCO-SA", value: "cisco-sa-19981105-ios-dfs-acl");
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

# Affected: 11.1
# no fix for 11.1, the matrix says "Go to 11.CA". tell the user to upgrade to the fix for that release
if (deprecated_version(version, '11.1')) {
 security_hole(port:0, extra: '\nUpdate to 11.1(22)CA or later\n'); exit(0);
}
# Affected: 11.1CA (core ED)
if (check_release(version: version,
                  patched: make_list("11.1(22)CA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CC (CEF ED)
if (check_release(version: version,
                  patched: make_list("11.1(21)CC1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CT (tag switch ED)
if (check_release(version: version,
                  patched: make_list("11.1(21.2)CT"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(16.1)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2F
# no fix for 11.2F, the matrix says "Go to 11.3". tell the user to upgrade to the fix for that release
if (deprecated_version(version, '11.2F')) {
 security_hole(port:0, extra: '\nUpdate to 11.3(7) or later\n'); exit(0);
}
# Affected: 11.2P (platform ED)
if (check_release(version: version,
                  patched: make_list("11.2(16.1)P"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2BC (CIP ED)
if (check_release(version: version,
                  patched: make_list("11.2(16.1)BC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3
if (check_release(version: version,
                  patched: make_list("11.3(6.2)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3T
if (check_release(version: version,
                  patched: make_list("11.3(6.2)T"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3NA (voice ED)
if (check_release(version: version,
                  patched: make_list("11.3(6.2)NA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3(2)XA
if (version == '11.3(2)XA') {
 security_hole(port:0, extra: '\nUpdate to 11.3(7) or later\n'); exit(0);
}

exit(0, "The remote host is not affected");
