#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:017
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17606);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0761", "CVE-2005-0762");
 
 name["english"] = "SUSE-SA:2005:017: ImageMagick";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:017 (ImageMagick).


This update fixes several security issues in the ImageMagick program suite:

- A format string vulnerability was found in the display program
which could lead to a remote attacker being to able to execute code
as the user running display by providing handcrafted filenames of
images. This is tracked by the Mitre CVE ID CVE-2005-0397.

Andrei Nigmatulin reported 4 problems in older versions of ImageMagick:

- A bug was found in the way ImageMagick handles TIFF tags.
It is possible that a TIFF image file with an invalid tag could
cause ImageMagick to crash.
This is tracked by the Mitre CVE ID CVE-2005-0759.

Only ImageMagick version before version 6 are affected.

- A bug was found in ImageMagick's TIFF decoder.
It is possible that a specially crafted TIFF image file could
cause ImageMagick to crash.
This is tracked by the Mitre CVE ID CVE-2005-0760.

Only ImageMagick version before version 6 are affected.

- A bug was found in the way ImageMagick parses PSD files.
It is possible that a specially crafted PSD file could cause
ImageMagick to crash.
This is tracked by the Mitre CVE ID CVE-2005-0761.

Only ImageMagick version before version 6.1.8 are affected.

- A heap overflow bug was found in ImageMagick's SGI parser.
It is possible that an attacker could execute arbitrary code
by tricking a user into opening a specially crafted SGI image
file.
This is tracked by the Mitre CVE ID CVE-2005-0762.

Only ImageMagick version before version 6 are affected." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_17_imagemagick.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/24");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the ImageMagick package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ImageMagick-5.5.4-125", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-5.5.4-125", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.4-125", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-5.5.4-125", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.7-233", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-5.5.7-233", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.7-233", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-5.5.7-233", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.7-225.15", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-5.5.7-225.15", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.5.7-225.15", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-5.5.7-225.15", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.0.7-4.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.0.7-4.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.0.7-4.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.0.7-4.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"SUSE8.2")
 || rpm_exists(rpm:"ImageMagick-", release:"SUSE9.0")
 || rpm_exists(rpm:"ImageMagick-", release:"SUSE9.1")
 || rpm_exists(rpm:"ImageMagick-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
 set_kb_item(name:"CVE-2005-0759", value:TRUE);
 set_kb_item(name:"CVE-2005-0760", value:TRUE);
 set_kb_item(name:"CVE-2005-0761", value:TRUE);
 set_kb_item(name:"CVE-2005-0762", value:TRUE);
}
