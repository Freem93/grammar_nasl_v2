#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:039
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13807);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SUSE-SA:2003:039: openssh (second release)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:039 (openssh (second release)).


The openssh package is the most widely used implementation of the secure
shell protocol family (ssh). It provides a set of network connectivity
tools for remote (shell) login, designed to substitute the traditional
BSD-style r-protocols (rsh, rlogin). openssh has various authentification
mechanisms and many other features such as TCP connection and X11 display
forwarding over the fully encrypted network connection as well as file
transfer facilities.

This is a new release of SUSE Security Announcement (openssh)," );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_039_openssh.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssh (second release) package";
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
if ( rpm_check( reference:"openssh-2.9.9p2-156", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-2.9.9p2-156", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.4p1-215", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.4p1-215", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.5p1-107", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
