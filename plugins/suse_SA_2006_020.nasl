#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:020
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21233);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:020: clamav";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:020 (clamav).


Clamav was updated to version 0.88.1 to fix the following security
problems:

- An integer overflow in the PE header parser (CVE-2006-1614).

- Format string bugs in the logging code could potentially be
exploited to execute arbitrary code (CVE-2006-1615).

- Access to invalid memory could lead to a crash (CVE-2006-1630)." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_20_clamav.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/17");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the clamav package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
