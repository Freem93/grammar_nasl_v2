#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0012
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13777);
 script_bugtraq_id(6689, 6690);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0057");
 
 name["english"] = "SUSE-SA:2003:0012: hypermail";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:0012 (hypermail).


Hypermail is a tool to convert a Unix mail-box file to a set of cross-
referenced HTML documents.
During an internal source code review done by Thomas Biege several bugs
where found in hypermail and its tools. These bugs allow remote code
execution, local tmp race conditions, denial-of-service conditions and
read access to files belonging to the host hypermail is running on.
Additionally the mail CGI program can be abused by spammers as email-
relay and should thus be disabled.

There is no temporary fix known other then disabling hypermail. Please
download and install the new packages from our FTP servers.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_12_hypermail.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the hypermail package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"hypermail-2.0b29-59", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hypermail-2.1.0-91", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hypermail-2.1.2-141", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hypermail-2.1.3-234", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hypermail-2.1.4-58", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hypermail-", release:"SUSE7.1")
 || rpm_exists(rpm:"hypermail-", release:"SUSE7.2")
 || rpm_exists(rpm:"hypermail-", release:"SUSE7.3")
 || rpm_exists(rpm:"hypermail-", release:"SUSE8.0")
 || rpm_exists(rpm:"hypermail-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0057", value:TRUE);
}
