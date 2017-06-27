#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:008
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24462);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:008: XFree86-server,xorg-x11-server,xloader";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:008 (XFree86-server,xorg-x11-server,xloader).


This update fixes three memory corruptions within the X server which
could be used by local attackers with access to this display to crash
the X server and potentially execute code.

CVE-2006-6101: Integer overflow in the ProcRenderAddGlyphs function
in the Render extension for X.Org 6.8.2, 6.9.0, 7.0,
and 7.1, and XFree86 X server, allows local users to
execute arbitrary code via a crafted X protocol request
that triggers memory corruption during processing of
glyph management data structures.

CVE-2006-6102: Integer overflow in the ProcDbeGetVisualInfo function
in the DBE extension for X.Org 6.8.2, 6.9.0, 7.0,
and 7.1, and XFree86 X server, allows local users to
execute arbitrary code via a crafted X protocol request
that triggers memory corruption during processing of
unspecified data structures.

CVE-2006-6103: Integer overflow in the ProcDbeSwapBuffers function in
the DBE extension for X.Org 6.8.2, 6.9.0, 7.0, and 7.1,
and XFree86 X server, allows local users to execute
arbitrary code via a crafted X protocol request
that triggers memory corruption during processing of
unspecified data structures." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_08_x.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the XFree86-server,xorg-x11-server,xloader package";
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
if ( rpm_check( reference:"xorg-x11-server-6.8.2-100.10", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.8.2-30.10", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
