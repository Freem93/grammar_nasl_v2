#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:044
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13765);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_cve_id("CVE-2002-1219", "CVE-2002-1221");
 
 name["english"] = "SUSE-SA:2002:044: bind8";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2002:044 (bind8).


The security research company ISS (Internet Security Services)
has discovered several vulnerabilities in the BIND8 name server,
including a remotely exploitable buffer overflow.


1.	There is a buffer overflow in the way named handles
SIG records. This buffer overflow can be exploited to
obtain access to the victim host under the account
the named process is running with.

2.	There are several Denial Of Service problems in BIND8
that allow remote attackers to terminate the name server
process.

Both vulnerabilities are addressed by this update, using patches
originating from ISC." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2002_004_bind8.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the bind8 package";
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
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bind8-", release:"SUSE7.0")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.1")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.2")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.3")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.0")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1219", value:TRUE);
 set_kb_item(name:"CVE-2002-1221", value:TRUE);
}
