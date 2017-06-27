#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:070
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24447);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:070: pdns";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:070 (pdns).


Two security problems that have been found in PowerDNS are fixed by this update:

CVE-2006-4251: The PowerDNS Recursor can be made to crash by sending
malformed questions to it over TCP potentially executing code.

CVE-2006-4252: Zero second CNAME TTLs can make PowerDNS exhaust allocated
stack space and crash." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_70_pdns.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the pdns package";
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
if ( rpm_check( reference:"pdns-2.9.17-7.3", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pdns-2.9.17-4.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
