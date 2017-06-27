#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:023
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13793);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SUSE-SA:2003:023: sendmail, sendmail-tls";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:023 (sendmail, sendmail-tls).


sendmail is the most widely used mail transport agent (MTA) in the
internet. A remotely exploitable buffer overflow has been found in all
versions of sendmail that come with SUSE products. These versions include
sendmail-8.11 and sendmail-8.12 releases. sendmail is the MTA subsystem
that is installed by default on all SUSE products up to and including
SUSE LINUX 8.0 and the SUSE LINUX Enterprise Server 7.

The vulnerability was discovered by Michal Zalewski. It is not related
to the vulnerability found by ISS in the first week of March as announced" );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_023_sendmail.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the sendmail, sendmail-tls package";
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
if ( rpm_check( reference:"sendmail-8.11.2-45", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.2-47", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.3-108", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.3-112", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.11.6-164", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-tls-8.11.6-166", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.3-75", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-109", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
