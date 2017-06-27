#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:018
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21150);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:018: RealPlayer";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:018 (RealPlayer).


This update fixes the following security problems in Realplayer:

- Specially crafted SWF files could cause a buffer overflow and
crash RealPlayer (CVE-2006-0323).

- Specially crafted web sites could cause heap overflow and lead to
executing arbitrary code (CVE-2005-2922). This was already fixed
with the previously released 1.0.6 version, but not announced on
request of Real.

The advisory for these problems is on this page at Real:
http://service.real.com/realplayer/security/03162006_player/en/

SUSE Linux 9.2 up to 10.0 and Novell Linux Desktop 9 are affected by
this problem and receive fixed packages.

If you are still using Realplayer on SUSE Linux 9.1 or SUSE Linux
Desktop 1, we again wish to remind you that the Real player on these
products cannot be updated and recommend to deinstall it." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_18_realplayer.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/27");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the RealPlayer package";
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
if ( rpm_check( reference:"RealPlayer-10.0.7-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.7-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.7-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
