#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:038
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19247);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2005:038: clamav";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:038 (clamav).


This security update upgrades the Clamav virus scan engine to
the version 0.68.1.

Among other bugfixes and improvements, this update fixes a bug in the
Quantum decompressor routines that can be used for a remote denial
of service attack against clamd.

This bug is tracked by the Mitre CVE ID CVE-2005-2056.

Also the Clam AV Mail Filter (clamav-milter) Plugin when used in sendmail
could be used for a remote denial of service attack.

This bug is tracked by the Mitre CVE ID CVE-2005-2070." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_38_clamav.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the clamav package";
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
if ( rpm_check( reference:"clamav-0.86.1-0.2", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.86.1-0.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.86.1-0.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.86.1-0.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.86.1-0.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
