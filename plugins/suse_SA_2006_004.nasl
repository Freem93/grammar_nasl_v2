#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:004
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20820);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:004: phpMyAdmin";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:004 (phpMyAdmin).


Stefan Esser discovered a bug in in the register_globals emulation
of phpMyAdmin that allowes to overwrite variables. An attacker could
exploit the bug to ultimately execute code (CVE-2005-4079).
Additionally several cross-site-scripting bugs were discovered
(CVE-2005-3787, CVE-2005-3665).

We have released a version update to phpMyAdmin-2.7.0-pl2 which
addresses the issues mentioned above." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_04_phpmyadmin.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/29");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the phpMyAdmin package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"phpMyAdmin-2.7.0pl2-1.2", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.7.0pl2-3", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.7.0pl2-1.2", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.7.0pl2-1.2", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.7.0pl2-1.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
