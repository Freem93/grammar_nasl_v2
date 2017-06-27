#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:058
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24436);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:058: openssl";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:058 (openssl).


Several security problems were found and fixed in the OpenSSL
cryptographic library.

CVE-2006-3738/VU#547300:
A Google security audit found a buffer overflow condition within the
SSL_get_shared_ciphers() function which has been fixed.

CVE-2006-4343/VU#386964:
The above Google security audit also found that the OpenSSL SSLv2
client code fails to properly check for NULL which could lead to a
server program using openssl to crash.

CVE-2006-2937:
Fix mishandling of an error condition in parsing of certain invalid
ASN1 structures, which could result in an infinite loop which consumes
system memory.

CVE-2006-2940:
Certain types of public key can take disproportionate amounts of time
to process. This could be used by an attacker in a denial of service
attack to cause the remote side top spend an excessive amount of time
in computation." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_58_openssl.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.7g-2.10", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7g-2.10", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7d-25.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7d-25.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7e-3.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7e-3.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
