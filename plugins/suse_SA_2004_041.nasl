#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:041
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15755);
 script_bugtraq_id(11694);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "SUSE-SA:2004:041: xshared, XFree86-libs, xorg-x11-libs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:041 (xshared, XFree86-libs, xorg-x11-libs).


The XPM library which is part of the XFree86/XOrg project is used by
several GUI applications to process XPM image files.
A source code review done by Thomas Biege of the SuSE Security-Team
revealed several different kinds of bugs.
The bug types are:
- integer overflows
- out-of-bounds memory access
- shell command execution
- path traversal
- endless loops
By providing a special image these bugs can be exploited by remote and/or
local attackers to gain access to the system or to escalate their local
privileges." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_41_xshared_XFree86_libs_xorg_x11_libs.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/18");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the xshared, XFree86-libs, xorg-x11-libs package";
 script_cve_id("CVE-2004-0914");
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
if ( rpm_check( reference:"xshared-4.2.0-269", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-132", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0.1-57", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.99.902-43.35.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.1-15.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
