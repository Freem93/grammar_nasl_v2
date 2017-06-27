#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:045
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24425);
 script_version ("$Revision: 1.6 $");

 name["english"] = "SUSE-SA:2006:045: freetype2";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:045 (freetype2).


This security update fixes crashes in the PCF handling of freetype2
which might be used to crash freetype2 using applications or even
to execute code in them." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_45_freetype2.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();


 summary["english"] = "Check for the version of the freetype2 package";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"freetype2-2.1.10-4.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.10-4.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-2.1.9-3.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.9-3.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-2.1.9-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freetype2-devel-2.1.9-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
