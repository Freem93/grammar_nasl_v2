# @DEPRECATED@
#
# This script has been deprecated and is no longer used 
# after a revamping of the Slackware generator.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from the SSA-2003-141-06a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18723);
script_version("$Revision: 1.7 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-141-06a security update');
script_set_attribute(attribute:'description', value: '
NOTE:  The original advisory quotes a section of the Slackware ChangeLog
which had inadvertently reversed the options to quotacheck.  The correct
option to use is \'m\'.  A corrected advisory follows:


An upgraded sysvinit package is available which fixes a problem with
the use of quotacheck in /etc/rc.d/rc.M.  The original version of
rc.M calls quotacheck like this:

    echo "Checking filesystem quotas:  /sbin/quotacheck -avugM"
    /sbin/quotacheck -avugM

The \'M\' option is wrong.  This causes the filesystem to be remounted,
and in the process any mount flags such as nosuid, nodev, noexec,
and the like, will be reset.  The correct option to use here is \'m\',
which does not attempt to remount the partition:

    echo "Checking filesystem quotas:  /sbin/quotacheck -avugm"
    /sbin/quotacheck -avugm

We recommend sites using file system quotas upgrade to this new package,
or edit /etc/rc.d/rc.M accordingly.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-141-06a");
script_summary(english: "SSA-2003-141-06a REVISED quotacheck security fix in rc.M ");
script_name(english: "SSA-2003-141-06a REVISED quotacheck security fix in rc.M ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute:'plugin_type', value: 'local');
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
 script_cvs_date("$Date: 2011/05/28 03:38:48 $");
script_end_attributes();
exit(0);
}

exit(0);

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.0", pkgname: "sysvinit", pkgver: "2.84", pkgnum:  "26", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sysvinit is vulnerable in Slackware 9.0
Upgrade to sysvinit-2.84-i386-26 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
