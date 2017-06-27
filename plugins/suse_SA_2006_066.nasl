#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:066
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24443);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:066: ImageMagick";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:066 (ImageMagick).


Two security problems were found in the GraphicsMagick tool set which
are also present in ImageMagick.

CVE-2006-5456: Multiple buffer overflows in ImageMagick allowed
user-assisted attackers to cause a denial of service and possibly
execute execute arbitrary code via (1) a DCM image that is not
properly handled by the ReadDCMImage function in coders/dcm.c, or
(2) a PALM image that is not properly handled by the ReadPALMImage
function in coders/palm.c.

Additionally a segfault regression when converting a PGM image was
fixed on SLE 10." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_66_imagemagick.html" );
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
if ( rpm_check( reference:"ImageMagick-6.2.3-4.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.2.3-4.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.2.3-4.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.2.3-4.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.2.3-4.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.1.8-6.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.1.8-6.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.1.8-6.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.1.8-6.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.1.8-6.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
