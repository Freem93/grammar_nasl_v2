#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0007
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13772);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0015");
 
 name["english"] = "SUSE-SA:2003:0007: cvs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:0007 (cvs).


CVS (Concurrent Versions System) is a version control system which
helps to manage concurrent editing of files by various authors.
Stefan Esser of e-matters reported a 'double free' bug in CVS
server code for handling directory requests. This free() call allows
an attacker with CVS read access to compromise a CVS server.
Additionally two features ('Update-prog' and 'Checkin-prog') were
disabled to stop clients with write access to execute arbitrary code
on the server. These features may be configurable at run-time in future
releases of CVS server.

There is no temporary fix known other then disable public access to the
CVS server. You do not need to update the cvs package as long as you
need 'Update-prog' and 'Checkin-prog' feature and work in a trusted
environment.
Otherwise install the new packages from our FTP servers please.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_007_cvs.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2016/12/27 20:14:32 $");
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
if ( rpm_check( reference:"cvs-1.11-230", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11-231", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11-230", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-235", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-235", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"SUSE7.1")
 || rpm_exists(rpm:"cvs-", release:"SUSE7.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE7.3")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0015", value:TRUE);
}
