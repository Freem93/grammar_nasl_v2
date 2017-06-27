#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:050
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24428);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:050: ImageMagick";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:050 (ImageMagick).


Several security problems have been fixed in ImageMagick:

- CVE-2006-3744: Several heap buffer overflows were found in the Sun
Bitmap decoder of ImageMagick during an audit by the Google Security
Team. This problem could be exploited by an attacker to execute code.

- CVE-2006-3743: Multiple buffer overflows were found by the Google
Security team in the XCF handling due to incorrect bounds checking.
This problem could be exploited by an attacker to execute code.

- CVE-2006-4144: An integer overflow in the ReadSGIImage function can
be used by attackers to potentially execute code.

- An infinite loop in ImageMagick caused by TransformHSB was fixed.

- An infinite loop in the handling of TIFF images was fixed." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_50_imagemagick.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the ImageMagick package";
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
if ( rpm_check( reference:"ImageMagick-6.2.3-4.4", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.2.3-4.4", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.2.3-4.4", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.2.3-4.4", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.2.3-4.4", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.0.7-4.10", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.0.7-4.10", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.0.7-4.10", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7-4.10", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.0.7-4.10", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.1.8-6.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.1.8-6.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.1.8-6.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.1.8-6.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.1.8-6.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
