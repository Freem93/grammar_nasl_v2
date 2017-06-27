#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:055
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24433);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:055: openssl,mozilla-nss";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:055 (openssl,mozilla-nss).


If an RSA key with exponent 3 is used it may be possible to forge a
PKCS verify the certificate if they are not checking for excess data
in the RSA exponentiation result of the signature.

This problems affects various SSL implementations. This advisory
covers the following implementations:

- OpenSSL (CVE-2006-4339)
- Mozilla NSS (CVE-2006-4340 and CVE-2006-4341)
for SUSE Linux 10.0, 10.1 and SUSE Linux Enterprise 10.

Implementations that are affected and still need to be updated:
- gnutls in all distributions.
- Mozilla NSS before SUSE Linux 10.0 and SUSE Linux Enterprise 10.

The official openssl advisory is here:
http://www.openssl.org/news/secadv_20060905.txt

Some details of the actual technical problem can be found here:
http://www.imc.org/ietf-openpgp/mail-archive/msg14307.html" );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_55_ssl.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssl,mozilla-nss package";
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
if ( rpm_check( reference:"mozilla-nss-3.10-12.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-3.10-12.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7g-2.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7g-2.8", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7d-25.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7d-25.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7e-3.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7e-3.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
