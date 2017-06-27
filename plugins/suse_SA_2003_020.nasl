#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:020
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13790);
 script_bugtraq_id(7120);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0140");
 
 name["english"] = "SUSE-SA:2003:020: mutt";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:020 (mutt).


Mutt is a text-based Mail User Agent (MUA).
The IMAP-code of mutt is vulnerable to a buffer overflow that can be
exploited by a malicious IMAP-server to crash mutt or even execute
arbitrary code with the privileges of the user running mutt.

There is no temporary fix known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_020_mutt.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.3.12i-69", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.16i-92", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.22.1i-170", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.27i-77", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4i-216", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"SUSE7.1")
 || rpm_exists(rpm:"mutt-", release:"SUSE7.2")
 || rpm_exists(rpm:"mutt-", release:"SUSE7.3")
 || rpm_exists(rpm:"mutt-", release:"SUSE8.0")
 || rpm_exists(rpm:"mutt-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0140", value:TRUE);
}
