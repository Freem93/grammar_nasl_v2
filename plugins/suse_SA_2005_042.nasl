#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:042
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19251);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/11/03 18:08:43 $");
 
 name["english"] = "SUSE-SA:2005:042: acroread 5";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:042 (acroread 5).


This update fixes a buffer overflow in Acrobat Reader versions 5,
where an attacker could execute code by providing a handcrafted PDF
to the viewer.

The Acrobat Reader 5 versions of SUSE Linux 9.0 up to 9.2, SUSE
Linux Enterprise Server 9 and Novell Linux Desktop 9 were upgraded
to Acrobat Reader 7.

Unfortunately this version upgrade introduces new dependencies. Please
use the YaST module 'Install or Remove Software' to check if there
are new dependencies and install the required packages.

Since Adobe does no longer provide updated packages that work on SUSE
Linux Enterprise Server 8, United Linux 1, and SUSE Linux Desktop 1
we are unable to provide fixed packages for these products.

The SUSE Security Team strongly advises to deinstall the acroread
package on these platforms and use alternate PDF viewers like xpdf,
kpdf, gpdf or gv.

Since this attack could be done via E-Mail messages or web pages,
this should be considered to be remote exploitable.

This issue is tracked by the Mitre CVE ID CVE-2005-1625." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_42_acroread.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the acroread 5 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-7.0.0-9", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-5.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-7.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
