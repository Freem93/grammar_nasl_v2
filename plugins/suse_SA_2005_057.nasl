#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:057
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19936);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2005:057: opera";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:057 (opera).


This update upgrades the Opera web browser to the 8.50 release.

Besides the changes in 8.50 that are listed in
http://www.opera.com/docs/changelogs/linux/850/
following security problems were fixed:

1. Attached files are opened without any warnings directly from the 
user's cache directory. This can be exploited to execute arbitrary 
Javascript in context of 'file://'. 

2. Normally, filename extensions are determined by the 'Content-Type'  
in Opera Mail. However, by appending an additional '.' to the end of 
a filename, an HTML file could be spoofed to be e.g. 'image.jpg.'.

These two vulnerabilities combined may be exploited to conduct script
insertion attacks if the user chooses to view an attachment named
e.g. 'image.jpg.' e.g. resulting in disclosure of local files." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_57_opera.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/05");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the opera package";
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
if ( rpm_check( reference:"opera-8.50-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.50-3", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.50-1.1", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.50-2.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.50-2.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
