#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:031
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19240);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2005:031: opera";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:031 (opera).


The commercial web browser Opera has been updated to the 8.0 version,
fixing all currently known security problems, including:

- CVE-2005-0235: IDN cloaking / homograph attack allows easy 
spoofing of domain names.

- CVE-2005-0456: Opera did not validate base64 encoded binary in data:
URLs correctly.

- CVE-2005-1139: Opera showed the Organizational Information of SSL
certificates which could be easily spoofed and be used for phishing
attacks.

A full Changelog can be found on:
http://www.opera.com/linux/changelogs/800/" );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_31_opera.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
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
if ( rpm_check( reference:"opera-8.0-4", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.0-4", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.0-1.1", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.0-1.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.0-1.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
