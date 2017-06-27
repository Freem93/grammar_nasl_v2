#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:014
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13785);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0411");
 
 name["english"] = "SuSE-SA:2003:014: kdelibs/kdelibs3";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:014 (kdelibs/kdelibs3).


The kdelibs3 (kdelibs for SLES7 based products) package is a core package
for the K desktop environment (KDE). The URI handler of the kdelibs3
and kdelibs class library contains a flaw which allows remote
attackers to create arbitrary files as the user utilizing the
kdelibs3/kdelibs package.
Affected are applications which use the kdelibs3/kdelibs URI handler
such as Konqueror or Kmail.
The original KDE advisory can be found at
http://www.kde.org/info/security/advisory-20040517-1.html


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_14_kdelibs.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kdelibs/kdelibs3 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs3-3.0-120", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.0.5-54", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.1.1-139", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.1.4-51", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.2.1-44.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"SUSE8.0")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE8.1")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE8.2")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE9.0")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}
