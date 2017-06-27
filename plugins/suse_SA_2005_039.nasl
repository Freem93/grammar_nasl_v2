#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:039
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19248);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "SUSE-SA:2005:039: zlib";
 
 script_bugtraq_id(14162);
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:039 (zlib).


A denial of service condition was fixed in the zlib library.

Any program using zlib to decompress data can be crashed by a specially
handcrafted invalid data stream. This includes web browsers or email
programs able to view PNG images (which are compressed by zlib),
allowing remote attackers to crash browser sessions or potentially
anti virus programs using this vulnerability.

This issue is tracked by the Mitre CVE ID CVE-2005-2096.

Since only zlib 1.2.x is affected, older SUSE products are not affected
by this problem." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_39_zlib.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the zlib package";
 script_cve_id("CVE-2005-2096");
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"zlib-1.2.1-70.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-70.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.1-74.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-74.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.2-5.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.2-5.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
