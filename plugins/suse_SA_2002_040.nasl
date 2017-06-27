#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:040
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13761);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SUSE-SA:2002:040: lprng, html2ps";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2002:040 (lprng, html2ps).


The lprng package contains the 'runlpr' program which allows the lp
user to execute the lpr program as root. Local attackers can pass
certain commandline arguments to lpr running as root, fooling it
to execute arbitrary commands as root. This has been fixed.
Note that this vulnerability can only be exploited if the attacker
has previously gained access to the lp account.

Additionally, the html2ps printfilter, which is installed as part of
the LPRng print system, allowed remote attackers to execute arbitrary
commands in the context of the lp user.

These two issues combined allow attackers to mount a remote root attack.

As a workaround, we recommend to uninstall the html2ps package, and
restrict access to your print services to authorized hosts only.

Access control to lpd is implemented by adding appropriate entries to the
/etc/lpd.perms file. Please consult the lpd.perms(5) manpage, or add the
single line

DEFAULT REJECT

to your /etc/lpd.perms file to deny access to everyone from the outside.


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2002_040_lprng_html2ps.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the lprng, html2ps package";
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
if ( rpm_check( reference:"html2ps-1.0b1-428", release:"SUSE7.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"html2ps-1.0b1-431", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"html2ps-1.0b1-432", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"html2ps-1.0b3-457", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"html2ps-1.0b3-456", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lpdfilter-0.42-155", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"html2ps-1.0b3-458", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lpdfilter-0.43-63", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
