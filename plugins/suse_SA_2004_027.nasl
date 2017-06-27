#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:027
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14322);
 script_bugtraq_id(10977);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
 
 name["english"] = "SUSE-SA:2004:027: qt3/qt3-non-mt/qt3-32bit/qt3-static";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:027 
(qt3/qt3-non-mt/qt3-32bit/qt3-static).


The QT-library is an environment for GUI-programming and is used in
various well-known projects, like KDE.

There is a heap overflow in the BMP image format parser.  An
attacker, exploiting this flaw, would need to be able to coerce
a local user or program to process a specially crafted image
file.  Upon successful exploitation, the attacker would be able
to execute arbitrary code.

In addition, there are 2 distinct flaws within the XPM parser
which, when exploited, lead to a Denial of Service (DoS)." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_27_qt3.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the qt3 packages";
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
if ( rpm_check( reference:"qt3-3.0.5-167", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-non-mt-3.0.5-231", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-static-3.0.5-159", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-3.1.1-118", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-non-mt-3.1.1-125", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-static-3.1.1-124", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-3.2.1-68", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-non-mt-3.2.1-70", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-static-3.2.1-70", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-3.3.1-36.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-non-mt-3.3.1-41.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"qt3-static-3.3.1-41.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"qt3-", release:"SUSE8.1")
 || rpm_exists(rpm:"qt3-", release:"SUSE8.2")
 || rpm_exists(rpm:"qt3-", release:"SUSE9.0")
 || rpm_exists(rpm:"qt3-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0692", value:TRUE);
 set_kb_item(name:"CVE-2004-0693", value:TRUE);
}
