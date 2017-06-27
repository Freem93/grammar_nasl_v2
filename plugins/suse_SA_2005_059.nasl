#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:059
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19996);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2005:059: RealPlayer";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:059 (RealPlayer).


The following security issue in RealPlayer was fixed:

- A format string bug in the RealPix (.rp) file format parser
(CVE-2005-2710).

This bug allowed remote attackers to execute arbitrary code by
supplying a specially crafted file, e.g via Web page or E-Mail.

Note that we no longer support RealPlayer on the following distributions
for some time now:
- SUSE Linux 9.1
- SUSE Linux 9.0
- SUSE Linux Desktop 1.0

On these distributions, please deinstall RealPlayer by running as root:
	rpm -e RealPlayer" );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_59_RealPlayer.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/11");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the RealPlayer package";
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
if ( rpm_check( reference:"RealPlayer-10.0.6-3.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.6-1.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.6-1.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
