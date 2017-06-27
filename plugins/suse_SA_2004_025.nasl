#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:025
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14264);
 script_bugtraq_id(10865);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0500");
 
 name["english"] = "SUSE-SA:2004:025: gaim";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:025 (gaim).


Gaim is an instant messaging client which supports a wide range of
protocols.

Sebastian Krahmer of the SuSE Security Team discovered various remotely
exploitable buffer overflows in the MSN-protocol parsing functions during
a code review of the MSN protocol handling code.

Remote attackers can execute arbitrary code as the user running the gaim
client.

The vulnerable code exists in SUSE Linux 9.1 only." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_25_gaim.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/12");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the gaim package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gaim-0.75-79.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0500", value:TRUE);
}
