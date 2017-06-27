#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:015
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13831);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
 
 name["english"] = "SuSE-SA:2004:015: cvs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:015 (cvs).


The Concurrent Versions System (CVS) offers tools which allow developers
to share and maintain large software projects.
Various remotely exploitable conditions have been found during a
source code review of CVS done by Stefan Esser and Sebastian Krahmer
(SuSE Security-Team).
These bugs allow remote attackers to execute arbitrary code as the user
the CVS server runs as. Since there is no easy workaround we strongly
recommend to update the cvs package.
The update packages fix vulnerabilities which have been assigned the
CAN numbers CVE-2004-0416, CVE-2004-0417 and CVE-2004-0418.
The cvs packages shipped by SUSE (as well as our recent updates for CVS)
are not vulnerable to CVE-2004-0414.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_15_cvs.html" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119);




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2016/01/14 15:30:09 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.1p1-332", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-332", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.5-114", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.6-83", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-24.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"SUSE8.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.1")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
}
