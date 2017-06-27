#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:014
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24411);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:014: bind";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:014 (bind).


Two security problems were fixed in the ISC BIND nameserver
version 9.3.4, which are addressed by this advisory:

CVE-2007-0493: If recursion is enabled, a remote attacker can dereference
a freed fetch context causing the daemon to abort / crash.

CVE-2007-0494: By sending specific DNS query responses with multiple
RRSETS attackers could cause BIND to exit abnormally.

Updates for SUSE Linux Enterprise Server were released on Friday 26th of January,
updates for SUSE Linux and openSUSE were released on Monday 29th of January." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_14_bind.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the bind package";
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
if ( rpm_check( reference:"bind-9.3.2-56.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind-libs-9.3.2-56.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-56.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind-9.3.2-56.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind-libs-9.3.2-56.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-56.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
