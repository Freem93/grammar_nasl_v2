#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:039
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24419);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:039: kdebase3-kdm";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:039 (kdebase3-kdm).


The KDE Display Manager KDM stores the type of the previously used
session in the user's home directory.

By using a symlink a local attacker could trick kdm into also storing
content of files that are normally not accessible by users, like for
instance /etc/shadow.

This problem is tracked by Mitre CVE ID CVE-2006-2449 and was
found by Ludwig Nussel of the SUSE Security Team." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_39_kdm.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kdebase3-kdm package";
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
if ( rpm_check( reference:"kdebase3-kdm-3.4.2-27.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase3-kdm-3.2.1-68.53", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase3-kdm-3.3.0-29.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase3-kdm-3.4.0-28.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
