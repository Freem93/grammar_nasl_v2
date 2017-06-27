#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:019
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13789);
 script_bugtraq_id(7049);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0081");
 
 name["english"] = "SUSE-SA:2003:019: ethereal";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:019 (ethereal).


Ethereal is a GUI for analyzing and displaying network traffic.
Ethereal is vulnerable to a format string bug in it's SOCKS code
and to a heap buffer overflow in it's NTLMSSP code.
These bugs can be abused to crash ethereal or maybe to execute
arbitrary code on the machine running ethereal.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_019_ethereal.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.9.6-156", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-155", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-154", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-153", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.6-152", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"SUSE7.1")
 || rpm_exists(rpm:"ethereal-", release:"SUSE7.2")
 || rpm_exists(rpm:"ethereal-", release:"SUSE7.3")
 || rpm_exists(rpm:"ethereal-", release:"SUSE8.0")
 || rpm_exists(rpm:"ethereal-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0081", value:TRUE);
}
