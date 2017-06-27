# @DEPRECATED@
#
# This script has been deprecated and is no longer used 
# after a revamping of the Slackware generator.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from the SSA-2004-222-01b
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37950);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-222-01b security update');
script_set_attribute(attribute:'description', value: '[slackware-security]  Sendmail buffer overflow fixed (NEW)

The sendmail packages in Slackware 8.0, 8.1, and 9.0 have been patched
to fix a security problem.  Note that this vulnerablity is NOT the same
one that was announced on March 3rd and requires a new fix.

All sites running sendmail should upgrade.  

More information on the problem can be found here:

http://www.sendmail.org/8.12.9.html

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-222-01b");
script_summary(english: "SSA-2004-222-01b Sendmail buffer overflow fixed (NEW)");
script_name(english: "SSA-2004-222-01b Sendmail buffer overflow fixed (NEW)");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute:'plugin_type', value: 'local');
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_cvs_date("$Date: 2011/05/28 03:38:48 $");
script_end_attributes();
exit(0);
}

exit(0);

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "sendmail", pkgver: "8.12.9", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sendmail is vulnerable in Slackware 8.1
Upgrade to sendmail-8.12.9-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "sendmail-cf", pkgver: "8.12.9", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sendmail-cf is vulnerable in Slackware 8.1
Upgrade to sendmail-cf-8.12.9-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sendmail", pkgver: "8.12.9", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sendmail is vulnerable in Slackware 9.0
Upgrade to sendmail-8.12.9-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sendmail-cf", pkgver: "8.12.9", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sendmail-cf is vulnerable in Slackware 9.0
Upgrade to sendmail-cf-8.12.9-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
