#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:047
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19926);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2011/11/03 18:08:43 $");
 
 name["english"] = "SUSE-SA:2005:047: acroread";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:047 (acroread).


A buffer overflow was found in the core application plug-in for the
Adobe Reader, that allows attackers to cause a denial of service
(crash) and possibly execute arbitrary code via unknown vectors.

This is tracked by the Mitre CVE ID CVE-2005-2470.

Note that for SUSE Linux Enterprise Server 8 and SUSE Linux Desktop 1
Acrobat Reader support was already discontinued by an earlier
announcement." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_47_acroread.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/05");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the acroread package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-7.0.1-3", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
