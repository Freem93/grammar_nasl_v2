#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:039
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15569);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(11501);
 script_cve_id("CVE-2004-0888", "CVE-2004-0889");
 
 name["english"] = "SUSE-SA:2004:039: xpdf, gpdf, kdegraphics3-pdf, pdftohtml, cups";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:039 (xpdf, gpdf, kdegraphics3-pdf, pdftohtml, cups).


Xpdf is a widely used fast PDF file viewer. Various other PDF viewer
and PDF conversion tools use xpdf code to accomplish their tasks.
Chris Evans found several integer overflows and arithmetic errors.
Additionally Sebastian Krahmer from the SuSE Security-Team found similar
bugs in xpdf 3.
These bugs can be exploited by tricking an user to open a malformated PDF
file. As a result the PDF viewer can be crashed or may be even code can be
executed." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_39_pdftools_cups.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/26");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the xpdf, gpdf, kdegraphics3-pdf, pdftohtml, cups package";
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
if ( rpm_check( reference:"xpdf-1.01-255", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.01-137", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pdftohtml-0.36-118", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.02pl1-141", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pdftohtml-0.36-112.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-64.21", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpdf-0.112.1-26.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-pdf-3.2.1-67.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"SUSE8.1")
 || rpm_exists(rpm:"xpdf-", release:"SUSE8.2")
 || rpm_exists(rpm:"xpdf-", release:"SUSE9.0")
 || rpm_exists(rpm:"xpdf-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-0889", value:TRUE);
}
