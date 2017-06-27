#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:053
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24431);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:053: flash-player";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:053 (flash-player).


Multiple input validation errors have been identified in the Macromedia
Flash Player that could lead to the potential execution of arbitrary
code.

These vulnerabilities could be accessed through content delivered
from a remote location via the user's web browser, email client,
or other applications that include or reference the Flash
Player. (CVE-2006-3311, CVE-2006-3587, CVE-2006-3588)

These updates also include changes to prevent circumvention of the
'allowScriptAccess' option. (CVE-2006-4640)" );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_53_flashplayer.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the flash-player package";
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
if ( rpm_check( reference:"flash-player-7.0.68.0-1.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.68.0-1.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.68.0-1.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
