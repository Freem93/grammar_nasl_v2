#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:041
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24421);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:041: acroread";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:041 (acroread).


Various unspecified security problems have been fixed in Acrobat
Reader version 7.0.8.

Adobe does not provide detailed information about the nature of the
security problems. Therefore, it is necessary to assume that remote
code execution is possible.


Adobe does not provide update packages for Acroread that are compatible
with some of our releases from the past. Therefore, updates are missing
(and might not be provided) for the products listed as follows.

As a solution to Adobe acroread security problems on older products
we suggest removal of the package from exposed systems and to use
the longer maintained open source PDF viewers.

- SUSE Linux Enterprise Server 9, Open Enterprise Server,
Novell Linux POS 9

Acrobat Reader 7.0.8 has a new requirement on GTK+ 2.4 libraries
(previously GTK+ 2.2).

Since the above products contain only GTK+ 2.2, the Acrobat Reader
7.0.8 provided by Adobe is currently not functional.

We have postponed the updates and wait for Adobe to clarify this
problem.

- SUSE Linux Enterprise Server 8, SUSE Linux Enterprise Desktop 1

These versions only support Acrobat Reader 5 and could not be
upgraded for Acrobat Reader 7 due to glibc and GTK+ requirements.

We discontinued security support for Acrobat Reader on those
products some time ago already.

This issue is tracked by the Mitre CVE ID CVE-2006-3093." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_41_acroread.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the acroread package";
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
if ( rpm_check( reference:"acroread-7.0.8-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.8-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.8-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
