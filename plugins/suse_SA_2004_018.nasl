#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:018
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13834);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0413");

 name["english"] = "SuSE-SA:2004:018: subversion";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:018 (subversion).


Subversion is a version control system like the well known CVS.
The subversion code is vulnerable to a remotely exploitable buffer
overflow on the heap. The bug appears before any authentication took
place. An attacker is able to execute arbitrary code by abusing this
vulnerability.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_18_subversion.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();


 summary["english"] = "Check for the version of the subversion package";
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
if ( rpm_check( reference:"subversion-0.23.0-60", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-0.17.1-98", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-0.27.0-209", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-1.0.0-73.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"subversion-", release:"SUSE8.1")
 || rpm_exists(rpm:"subversion-", release:"SUSE8.2")
 || rpm_exists(rpm:"subversion-", release:"SUSE9.0")
 || rpm_exists(rpm:"subversion-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0413", value:TRUE);
}
