#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:080
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24455);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SUSE-SA:2006:080: MozillaFirefox,MozillaThunderbird";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:080 (MozillaFirefox,MozillaThunderbird).


This security update brings the current set of Mozilla security updates, with
following versions:

- Mozilla Firefox to version 1.5.0.9 for Novell Linux Desktop 9,
SUSE Linux Enterprise 10 and SUSE Linux 9.3 up to 10.1.

- Mozilla Firefox to version 2.0.0.1 for openSUSE 10.2.

- Mozilla Thunderbird to version 1.5.0.9 for SUSE Linux 9.3 up to
10.1 and openSUSE 10.2.

These updates were released on December 22nd but due to Christmas
holidays got announced today.

Updated SeaMonkey packages will be released soon.

More Details regarding the problems can be found on this page:
http://www.mozilla.org/projects/security/known-vulnerabilities.html" );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_80_mozilla.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the MozillaFirefox,MozillaThunderbird package";
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
if ( rpm_check( reference:"MozillaFirefox-1.5.0.9-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.9-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.9-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.5.0.9-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.9-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.9-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
