#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:026
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14276);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2004:026: rsync";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:026 (rsync).


The rsync-team released an advisory about a security problem in rsync.
If rsync is running in daemon-mode and without a chroot environment it
is possible for a remote attacker to trick rsyncd into creating an
absolute pathname while sanitizing it.

As a result it is possible to read/write from/to files outside the
rsync directory.

NOTE: SUSE LINUX ships the rsync daemon with a chroot environment enabled
by default, therefore the default setup is not vulnerable." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_26_rsync.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/16");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the rsync package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"rsync-2.6.2-25", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.6.2-26", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.6.2-26", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.6.2-8.9", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
