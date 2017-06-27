#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:013
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24466);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:013: xine-ui,xine-lib,xine-extra,xine-devel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:013 (xine-ui,xine-lib,xine-extra,xine-devel).


This update fixes several format string bugs that can be exploited remotely
with user-assistance to execute arbitrary code.
Since SUSE Linux version 10.1 format string bugs are not exploitable
anymore. (CVE-2007-0017)" );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_13_xine.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the xine-ui,xine-lib,xine-extra,xine-devel package";
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
if ( rpm_check( reference:"xine-extra-1.1.0-0.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.0-0.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-0.99.4-84.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xine-lib-1.0-10.14", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-1.0-10.14", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
