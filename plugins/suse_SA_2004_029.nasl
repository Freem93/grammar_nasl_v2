#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:029
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14658);
 script_bugtraq_id(11051);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0797");
 
 name["english"] = "SUSE-SA:2004:029: zlib";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:029 (zlib).


zlib is a widely used data compression library. Programs linked against it
include most desktop applications as well as servers such as Apache and
OpenSSH.

The 'inflate' function of zlib handles certain input data
incorrectly which could lead to a denial of service condition for
programs using it with untrusted data. Whether the vulnerability
can be exploided locally or remotely depends on the application
using it.

zlib versions older than version 1.2 are not affected." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_29_zlib.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib-1.2.1-70.6", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-70.6", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0797", value:TRUE);
}
