#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:062
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24440);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:062: openssh";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:062 (openssh).


Several security problems were fixed in OpenSSH 4.4 and the bug fixes were
back ported to the openssh versions in our products.

- CVE-2006-4924: A denial of service problem has been fixed in OpenSSH which could
be used to cause lots of CPU consumption on a remote openssh server.

- CVE-2006-4925: If a remote attacker is able to inject network traffic this could
be used to cause a client connection to close.

- CVE-2006-5051: Fixed an unsafe signal handler reported by Mark Dowd. The signal
handler was vulnerable to a race condition that could be exploited to perform a
pre-authentication denial of service. This vulnerability could theoretically lead to
pre-authentication remote code execution if GSSAPI authentication is enabled,
but the likelihood of successful exploitation appears remote.

- CVE-2006-5052: Fixed a GSSAPI authentication abort that could be used to determine
the validity of user names on some platforms." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_62_openssh.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssh package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-4.1p1-10.9", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.1p1-10.9", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-3.10", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-3.10", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-12.8", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-12.8", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
