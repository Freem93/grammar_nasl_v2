# @DEPRECATED@
#
# This script has been deprecated and is no longer used 
# after a revamping of the Slackware generator.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18704);
script_version("$Revision: 1.8 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005-2010 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update." );
 script_set_attribute(attribute:"description", value:
"New Samba packages are available for Slackware 8.1 and -current
to fix a security problem and provide other bugfixes and improvements." );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
script_end_attributes();


script_summary("SSA New Samba package available");
name["english"] = "SSA-18704 New Samba package available";
script_name(english:name["english"]);exit(0);
}

exit(0);

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "8.1", pkgname: "samba", pkgver: "2.2.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 8.1
Upgrade to samba-2.2.7-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "samba", pkgver: "2.2.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 8.1
Upgrade to samba-2.2.7-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
