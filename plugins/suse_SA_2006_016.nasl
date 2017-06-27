#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:016
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21137);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:016: xorg-x11-server";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:016 (xorg-x11-server).


A programming flaw in the X.Org X Server allows local attackers to
gain root access when the server is setuid root, as is the default
in SUSE Linux 10.0.  This flaw was spotted by the Coverity project.

Only SUSE Linux 10.0 is affected, older products do not include the
problematic piece of code.

This problem is tracked by the Mitre CVE ID CVE-2006-0745." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_16_xorgx11server.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/23");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the xorg-x11-server package";
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
if ( rpm_check( reference:"xorg-x11-server-6.8.2-100.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
