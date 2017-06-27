#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:003
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24457);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2007:003: Sun Java";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:003 (Sun Java).


The SUN Java packages have been upgraded to fix security problems.

SUN Java was upgraded on all affected distributions:

- The Java 1.3 version to 1.3.1_19 for SUSE Linux Enterprise Server 8.

- The Java 1.4 version (also known as Java 2) to 1.4.2_13 for SUSE
Linux Enterprise Desktop 1, SUSE Linux Enterprise Server 9, SUSE
Linux 9.3, 10.0, 10.1 and openSUSE 10.2.

- The Java 1.5 version (also known as Java 5) to 1.5.0_10 for SUSE
Linux 9.3, 10.0, 10.1 and openSUSE 10.2.

While Sun does not publish the vulnerabilities fixed for this specific
update, it published the bugs fixed previously, text snippets verbatim
from the Mitre CVE DB:

CVE-2006-6731:Multiple buffer overflows in Sun Java Development
Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update 7 and
earlier, Java System Development Kit (SDK) and JRE 1.4.2_12 and
earlier 1.4.x versions, and SDK and JRE 1.3.1_18 and earlier
allow attackers to develop Java applets that read, write, or
execute local files, possibly related to (1) integer overflows in
the Java_sun_awt_image_ImagingLib_convolveBI, awt_parseRaster,
and awt_parseColorModel functions; (2) a stack overflow in
the Java_sun_awt_image_ImagingLib_lookupByteRaster function;
and (3) improper handling of certain negative values in the
Java_sun_font_SunLayoutEngine_nativeLayout function.

CVE-2006-6736: Unspecified vulnerability in Sun Java Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 6 and earlier,
Java System Development Kit (SDK) and JRE 1.4.2_12 and earlier 1.4.x
versions, and SDK and JRE 1.3.1_18 and earlier allows attackers to
attackers to use untrusted applets to 'access data in other applets,'
aka 'The second issue.'

CVE-2006-6737: Unspecified vulnerability in Sun Java Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 5 and earlier,
Java System Development Kit (SDK) and JRE 1.4.2_10 and earlier 1.4.x
versions, and SDK and JRE 1.3.1_18 and earlier allows attackers to
use untrusted applets to 'access data in other applets,' aka 'The
first issue.'

CVE-2006-6745: Multiple unspecified vulnerabilities in Sun Java
Development Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update
7 and earlier, and Java System Development Kit (SDK) and JRE 1.4.2_12
and earlier 1.4.x versions, allow attackers to develop Java applets or
applications that are able to gain privileges, related to serialization
in JRE." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_03_java.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the Sun Java package";
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
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.13-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.13-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_10-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
