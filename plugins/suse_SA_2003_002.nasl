#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:002
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13780);
 script_bugtraq_id(6475);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
 
 name["english"] = "SUSE-SA:2003:002: cups";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:002 (cups).


CUPS is a well known and widely used printing system for unix-like
systems. iDFENSE reported several security issues with CUPS that can
lead to local and remote root compromise. The following list
includes all vulnerabilities:
- integer overflow in HTTP interface to gain remote
access with CUPS privileges
- local file race condition to gain root (bug mentioned
above has to be exploited first)
- remotely add printers
- remote denial-of-service attack due to negative length in
memcpy() call
- integer overflow in image handling code to gain higher privileges
- gain local root due to buffer overflow of 'options' buffer
- design problem to gain local root (needs added printer, see above)
- wrong handling of zero width images can be abused to gain higher
privileges
- file descriptor leak and denial-of-service due to missing checks
of return values of file/socket operations

Since SUSE 8.1 CUPS is the default printing system.

As a temporary workaround CUPS can be disabled and an alternative
printing system like LPRng can be installed instead.

New CUPS packages are available on our FTP servers. Please, install
them to fix your system.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_002_cups.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.6-121", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.6-122", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.10-94", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.10-94", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.10-94", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.12-90", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.12-90", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.12-90", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.15-69", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.15-69", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.15-69", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"SUSE7.1")
 || rpm_exists(rpm:"cups-", release:"SUSE7.2")
 || rpm_exists(rpm:"cups-", release:"SUSE7.3")
 || rpm_exists(rpm:"cups-", release:"SUSE8.0")
 || rpm_exists(rpm:"cups-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1366", value:TRUE);
 set_kb_item(name:"CVE-2002-1367", value:TRUE);
 set_kb_item(name:"CVE-2002-1368", value:TRUE);
 set_kb_item(name:"CVE-2002-1369", value:TRUE);
 set_kb_item(name:"CVE-2002-1371", value:TRUE);
 set_kb_item(name:"CVE-2002-1372", value:TRUE);
 set_kb_item(name:"CVE-2002-1383", value:TRUE);
 set_kb_item(name:"CVE-2002-1384", value:TRUE);
}
