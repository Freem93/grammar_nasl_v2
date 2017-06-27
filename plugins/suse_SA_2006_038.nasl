#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:038
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24418);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:038: opera";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:038 (opera).


The web browser Opera has been upgraded to version 9.0 to add lots of
new features, and to fix the following security problem:

- CVE-2006-3198: An integer overflow vulnerability exists in the Opera
Web Browser due to the improper handling of JPEG files.

If excessively large height and width values are specified in
certain fields of a JPEG file, an integer overflow may cause Opera
to allocate insufficient memory for the image. This will lead to
a buffer overflow when the image is loaded into memory, which can
be exploited to execute arbitrary code.

- CVE-2006-3331: Opera did not reset the SSL security bar after
displaying a download dialog from an SSL-enabled website, which
allows remote attackers to spoof a trusted SSL certificate from an
untrusted website and facilitates phishing attacks." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_38_opera.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the opera package";
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
if ( rpm_check( reference:"opera-9.0-1.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-9.0-1.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-9.0-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
