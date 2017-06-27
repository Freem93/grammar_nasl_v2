#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:038
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15552);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(11506);
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-0929");
 
 name["english"] = "SUSE-SA:2004:038: libtiff";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2004:038 (libtiff).


libtiff is used by image viewers and web browser to view 'TIFF' images.
These usually open and display those images without querying the user,
making a normal system by default vulnerable to exploits of image
library bugs.

Chris Evans found several security related problems during an audit of
the image handling library libtiff, some related to buffer overflows,
some related to integer overflows and similar. This issue is being
tracked by the CVE ID CVE-2004-0803.

Matthias Claasen found a division by zero in libtiff. This is tracked
by the CVE ID CVE-2004-0804.

Further auditing by Dmitry Levin exposed several additional integer
overflows. These are tracked by the CVE ID CVE-2004-0886.

Additionally, iDEFENSE Security located a buffer overflow in the OJPEG
(old JPEG) handling in the SUSE libtiff package. This was fixed by
disabling the old JPEG support and is tracked by the CVE ID CVE-2004-0929.

SUSE wishes to thank all the reporters, auditors, and programmers
for helping to fix these problems." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_38_libtiff.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/22");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-38.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"SUSE8.1")
 || rpm_exists(rpm:"libtiff-", release:"SUSE8.2")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.0")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
 set_kb_item(name:"CVE-2004-0929", value:TRUE);
}
