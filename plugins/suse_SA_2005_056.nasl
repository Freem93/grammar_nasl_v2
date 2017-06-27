#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:056
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19935);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2005:056: XFree86-server,xorg-x11-server";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:056 (XFree86-server,xorg-x11-server).


The X server memory can be accessed my a malicious X client by exploiting
a missing range check in the function XCreatePixmap(). This bug can probably
be used to execute arbitrary code with the privileges of the X server (root)." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_56_xserver.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/05");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the XFree86-server,xorg-x11-server package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"XFree86-server-4.3.0.1-60", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-server-4.3.99.902-43.50.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.8.1-15.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.8.2-30.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
