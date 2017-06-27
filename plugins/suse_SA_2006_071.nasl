#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:071
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24448);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:071: phpMyAdmin";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:071 (phpMyAdmin).


The phpMyAdmin package was upgraded to version 2.9.1.1.

While we usually do not do version upgrades, fixing the occurring
security problems of phpMyAdmin got too difficult so we decided to
go with the current upstream version.

This release includes fixes for the previously not fixed security problems
tracked by the Mitre CVE IDs CVE-2006-3388, CVE-2006-5116, CVE-2006-5117,
and CVE-2006-5718 and of course all other bugs fixed in 2.9.1.1." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_71_phpmyadmin.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the phpMyAdmin package";
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
if ( rpm_check( reference:"phpMyAdmin-2.9.1.1-2.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.9.1.1-2.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
