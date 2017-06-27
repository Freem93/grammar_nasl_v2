#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:043
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15923);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013");
 
 name["english"] = "SUSE-SA:2004:043: cyrus-imapd";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:043 (cyrus-imapd).


Stefan Esser reported various bugs within the Cyrus IMAP Server.
These include buffer overflows and out-of-bounds memory access
which could allow remote attackers to execute arbitrary commands
as root. The bugs occur in the pre-authentication phase, therefore
an update is strongly recommended." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_43_cyrus_imapd.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/07");
  script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the cyrus-imapd package";
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
if ( rpm_check( reference:"cyrus-imapd-2.1.16-56", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.12-75", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.1.15-89", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.3-83.19", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-2.2.8-6.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cyrus-imapd-", release:"SUSE8.1")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE8.2")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.0")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.1")
 || rpm_exists(rpm:"cyrus-imapd-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1011", value:TRUE);
 set_kb_item(name:"CVE-2004-1012", value:TRUE);
 set_kb_item(name:"CVE-2004-1013", value:TRUE);
}
