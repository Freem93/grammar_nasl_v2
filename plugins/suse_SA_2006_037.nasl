#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:037
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24417);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:037: freetype2, freetype2-devel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:037 (freetype2, freetype2-devel).


The freetype2 library renders TrueType fonts for open source projects.
More than 900 packages on SUSE Linux use this library. Therefore the
integer overflows in this code found by Josh Bressers and Chris Evans
might have a high impact on the security of a desktop system.

The bugs can lead to a remote denial-of-service attack and may lead to
remote command execution. The user needs to use a program that uses
freetype2 (almost all GUI applications do) and let this program process
malicious font data." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_37.freetype.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the freetype2, freetype2-devel package";
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
if ( rpm_check( reference:"freetype2-2.1.10-4.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.10-4.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-2.1.9-3.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.9-3.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-2.1.9-4.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.9-4.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
