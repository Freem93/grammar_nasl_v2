#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:034
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14775);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 
 name["english"] = "SUSE-SA:2004:034: XFree86-libs, xshared";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:034 (XFree86-libs, xshared).


Chris Evans reported three vulnerabilities in libXpm which can
be exploited remotely by providing malformed XPM image files.
The function xpmParseColors() is vulnerable to an integer overflow
and a stack-based buffer overflow. The functions ParseAndPutPixels()
as well as ParsePixels() is vulnerable to a stack-based buffer overflow
too.
Additionally Matthieu Herrb found two one-byte buffer overflows." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_34_xfree86_libs_xshared.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/17");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the XFree86-libs, xshared package";
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
if ( rpm_check( reference:"xshared-4.2.0-267", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-127", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0.1-55", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.99.902-43.31", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"XFree86-libs-", release:"SUSE8.1")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE8.2")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE9.0")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
}
