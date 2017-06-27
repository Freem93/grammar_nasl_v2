#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:027
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13796);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_cve_id("CVE-2003-0028");
 
 name["english"] = "SUSE-SA:2003:027: glibc";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:027 (glibc).


Another integer overflow was found in glibc' XDR code. This bug is equal" );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_027_glibc.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the glibc package";
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
if ( rpm_check( reference:"glibc-2.2-26", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.2-68", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.4-78", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.5-177", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"SUSE7.1")
 || rpm_exists(rpm:"glibc-", release:"SUSE7.2")
 || rpm_exists(rpm:"glibc-", release:"SUSE7.3")
 || rpm_exists(rpm:"glibc-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2003-0028", value:TRUE);
}
