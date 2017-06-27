#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:035
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19244);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2005:035: razor-agents";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:035 (razor-agents).


Several bugs were fixed in Vipuls Razor spam detection framework.

These bugs could lead to remote denial-of-service conditions due to
processing malformed messages and possible stepping into infinite
loops." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_35_razor_agents.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the razor-agents package";
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
if ( rpm_check( reference:"razor-agents-2.126-122", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"razor-agents-2.34-54", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"razor-agents-2.36-59.4", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"razor-agents-2.61-3.2", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"razor-agents-2.67-3.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
