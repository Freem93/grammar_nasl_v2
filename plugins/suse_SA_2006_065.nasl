#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:065
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24442);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:065: ethereal";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:065 (ethereal).


Various problems have been fixed in the network analyzer Ethereal (now called
Wireshark), most of them leading to crashes of the ethereal program.

CVE-2006-5740: An unspecified vulnerability in the LDAP dissector
could be used to crash Ethereal.

CVE-2006-4574: A single \0 byte heap overflow was fixed in the MIME multipart
dissector. Potential of exploitability is unknown, but considered low.

CVE-2006-4805: A denial of service problem in the XOT dissector can cause
it to take up huge amount of memory and crash ethereal.

CVE-2006-5469: The WBXML dissector could be used to crash ethereal.

CVE-2006-5468: A NULL pointer dereference in the HTTP dissector could
crash ethereal." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_65_ethereal.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.13-2.14", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-devel-0.10.13-2.14", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.13-2.14", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
