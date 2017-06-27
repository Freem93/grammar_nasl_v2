#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:077
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24452);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:077: flash-player";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:077 (flash-player).


This security update brings the Adobe Flash Player to version 7.0.69.
The update fixes the following security problem:

CVE-2006-5330: CRLF injection vulnerabilities in Adobe Flash Player
allows remote attackers to modify HTTP headers of client requests
and conduct HTTP Request Splitting attacks via CRLF sequences in
arguments to the ActionScript functions (1) XML.addRequestHeader and
(2) XML.contentType.

The flexibility of the attack varies depending on the type of web
browser being used." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_77_flashplayer.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



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
if ( rpm_check( reference:"flash-player-7.0.69.0-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.69.0-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
