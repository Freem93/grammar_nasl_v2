#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:025
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21370);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:025: cyrus-sasl-digestmd5";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:025 (cyrus-sasl-digestmd5).


If a server or client is using DIGEST-MD5 authentication via the cyrus-sasl
libraries it is possible to cause a denial of service attack against the other
side (client or server) by leaving out the 'realm=' header in the authentication.

This is tracked by the Mitre CVE ID CVE-2006-1721." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_05_05.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/13");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the cyrus-sasl-digestmd5 package";
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
if ( rpm_check( reference:"cyrus-sasl-digestmd5-2.1.18-33.11", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-digestmd5-2.1.19-7.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-digestmd5-2.1.20-7.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
