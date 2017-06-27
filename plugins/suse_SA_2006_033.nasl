#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:033
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24414);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:033: awstats";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:033 (awstats).


This update fixes remote code execution vulnerabilities in the WWW
statistical analyzer awstats.

Since back porting awstats fixes is error prone we have upgraded it
to upstream version 6.6 which also includes new features.

Following security issues were fixed:
- CVE-2006-2237: missing sanitizing of the 'migrate' parameter. #173041
- CVE-2006-2644: missing sanitizing of the 'configdir' parameter. #173041
- Make sure open() only opens files for read/write by adding explicit <
and >." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_33_awstats.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the awstats package";
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
if ( rpm_check( reference:"awstats-6.6-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"awstats-6.6-0.1", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"awstats-6.6-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"awstats-6.6-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
