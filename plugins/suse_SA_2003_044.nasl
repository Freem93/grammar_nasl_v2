#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:044
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13812);
 script_bugtraq_id(8906, 8924);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2002-1562", "CVE-2003-0899");
 
 name["english"] = "SuSE-SA:2003:044: thttpd";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:044 (thttpd).


Two vulnerabilities were found in the 'tiny' web-server thttpd.
The first bug is a buffer overflow that can be exploited remotely
to overwrite the EBP register of the stack. Due to memory-alignment of
the stack done by gcc 3.x this bug can not be exploited. All thttpd
versions mentioned in this advisory are compiled with gcc 3.x and are
therefore not exploitable.
The other bug occurs in the virtual-hosting code of thttpd. A remote
attacker can bypass the virtual-hosting mechanism to read arbitrary
files.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_044_thttpd.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2016/12/27 20:14:32 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the thttpd package";
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
if ( rpm_check( reference:"thttpd-2.20b-175", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"thttpd-2.20c-98", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"thttpd-2.23beta1-163", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"thttpd-2.23beta1-164", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"thttpd-2.23beta1-165", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"thttpd-", release:"SUSE7.3")
 || rpm_exists(rpm:"thttpd-", release:"SUSE8.0")
 || rpm_exists(rpm:"thttpd-", release:"SUSE8.1")
 || rpm_exists(rpm:"thttpd-", release:"SUSE8.2")
 || rpm_exists(rpm:"thttpd-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2002-1562", value:TRUE);
 set_kb_item(name:"CVE-2003-0899", value:TRUE);
}
