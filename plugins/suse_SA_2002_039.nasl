#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:039
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13760);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SUSE-SA:2002:039: syslog-ng";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2002:039 (syslog-ng).


The syslog-ng package is a portable syslog implementation which can
be used as syslogd replacement.
Syslog-ng contained buffer overflows in its macro expansion routines.
These overflows could be triggered by remote attackers if certain
configuration options were enabled.
Syslog-ng is not used by default on SUSE LINUX, and even if installed,
the problematic options are not enabled by default. We recommend an update
of the syslog-ng package nevertheless if you use syslog-ng for logging.
To be sure the update takes effect you have to restart the daemon
by issuing the following command as root:

/etc/init.d/syslog-ng restart

We would like to thank Balazs Scheidler for offering fixes for this
problem.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2002_039_syslog_ng.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the syslog-ng package";
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
if ( rpm_check( reference:"syslog-ng-1.4.11-88", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"syslog-ng-1.4.11-89", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"syslog-ng-1.4.12-72", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"syslog-ng-1.4.14-319", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"syslog-ng-1.4.14-321", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
