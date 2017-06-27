#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:078
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24453);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SUSE-SA:2006:078: clamav";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:078 (clamav).


The anti virus scan engine ClamAV has been updated to version 0.88.7
to fix various security problems:

CVE-2006-5874: Clam AntiVirus (ClamAV) allows remote attackers to
cause a denial of service (crash) via a malformed base64-encoded MIME
attachment that triggers a NULL pointer dereference.

CVE-2006-6481: Clam AntiVirus (ClamAV) 0.88.6 allowed remote attackers
to cause a denial of service (stack overflow and application crash)
by wrapping many layers of multipart/mixed content around a document,
a different vulnerability than CVE-2006-5874 and CVE-2006-6406.

CVE-2006-6406: Clam AntiVirus (ClamAV) 0.88.6 allowed remote attackers
to bypass virus detection by inserting invalid characters into base64
encoded content in a multipart/mixed MIME file, as demonstrated with
the EICAR test file." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_78_clamav.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the clamav package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"clamav-0.88.7-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.7-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
