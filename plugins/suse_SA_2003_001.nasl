#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:001
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13775);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-1365");
 
 name["english"] = "SUSE-SA:2003:001: fetchmail";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:001 (fetchmail).


fetchmail is used to download emails from POP-, IMAP-, ETRN- or ODMR-
servers.
Stefan Esser of e-matters reported a bug in fetchmail's mail address
expanding code which can lead to remote system compromise.
When fetchmail expands email addresses in mail headers it doesn not
allocated enough memory. An attacker can send a malicious formatted mail
header to exhaust the memory allocated by fetchmail to overwrite parts of
the heap. This can be exploited to execute arbitrary code.

There is no temporary fix known. Please install the new packages from
our FTP servers.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_001_fetchmail.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the fetchmail package";
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
if ( rpm_check( reference:"fetchmail-5.6.5-40", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.8.0-78", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.0-280", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.0-279", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.13-54", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"SUSE7.1")
 || rpm_exists(rpm:"fetchmail-", release:"SUSE7.2")
 || rpm_exists(rpm:"fetchmail-", release:"SUSE7.3")
 || rpm_exists(rpm:"fetchmail-", release:"SUSE8.0")
 || rpm_exists(rpm:"fetchmail-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1365", value:TRUE);
}
