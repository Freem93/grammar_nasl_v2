#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:032
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19241);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/11/03 18:08:43 $");
 
 name["english"] = "SUSE-SA:2005:032: java2";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:032 (java2).


Two security bugs in the SUN Java implementation have been fixed.

Java Web Start can be exploited remotely due to an error in input
validation of tags in JNLP files, so an attacker can pass arbitrary
command-line options to the virtual machine to disable the sandbox
and get access to files.

This is tracked by the Mitre CVE ID CVE-2005-0836.

The second bug is equal to the first one but can also triggered by
untrusted applets.

This is tracked by the Mitre CVE ID CVE-2005-1974." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_32_java2.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the java2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"java2-1.4.2-144", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-144", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-1.4.2-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-144", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-1.4.2-129.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java2-jre-1.4.2-129.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.08-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.08-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
