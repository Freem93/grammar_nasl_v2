#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:043
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24423);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:043: apache,apache2";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:043 (apache,apache2).


The following security problem was fixed in the Apache and Apache 2
web servers:

mod_rewrite: Fix an off-by-one security problem in the ldap scheme
handling. For some RewriteRules this could lead to a pointer being
written out of bounds. Depending on stack alignment this could be
used to potentially execute code.

The mod_rewrite module is not enabled per default in our packages.

This problem is tracked by the Mitre CVE ID CVE-2006-3747.

A more detailed description of this problem is available in:

	   http://www.apache.org/dist/httpd/Announcement2.0.html

For SUSE Linux 10.0, 10.1 and SUSE Linux Enterprise 10 additionally
a old bug was fixed that we missed to forward port to the Apache 2.2
packages:

mod_imap: Fixes a cross-site-scripting bug in the imagemap module.
This issue is tracked by the Mitre CVE ID CVE-2005-3352." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_43_apache.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the apache,apache2 package";
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
if ( rpm_check( reference:"apache2-2.0.54-10.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.54-10.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.54-10.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.50-7.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.50-7.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.50-7.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.53-9.12", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.53-9.12", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.53-9.12", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
