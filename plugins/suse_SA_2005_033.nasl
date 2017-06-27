#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:033
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19242);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2005:033: spamassassin";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:033 (spamassassin).


The anti spam tool SpamAssassin was prone to a denial-of-service
attack. A remote attacker could craft a MIME E-Mail message that
would waste a lot of CPU cycles parsing the Content-Type header.

This is tracked by the Mitre CVE ID CVE-2005-1266.

Only SUSE Linux 9.2 and 9.3 are affected, since they include the 3.x
version of spamassassin. Older versions are not affected." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_33_spamassassin.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the spamassassin package";
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
if ( rpm_check( reference:"perl-spamassassin-3.0.4-1.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-1.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"perl-spamassassin-3.0.4-1.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"spamassassin-3.0.4-1.1", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
