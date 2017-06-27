#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:005
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24459);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:005: w3m";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:005 (w3m).


A format string problem in w3m -dump / -backend mode could be used
by a malicious server to crash w3m or execute code.

In SUSE Linux 10.1, openSUSE 10.2 and SUSE Linux Enterprise Server
and Desktop 10 this problem was not exploitable to execute code due
to use of the FORTIFY SOURCE extensions.

This problem is tracked by the Mitre CVE ID CVE-2006-6772." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_05_w3m.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the w3m package";
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
if ( rpm_check( reference:"w3m-0.5.1-6.2", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"w3m-0.5.1-4.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
