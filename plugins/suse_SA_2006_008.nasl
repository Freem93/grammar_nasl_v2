#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:008
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20923);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:008: openssh";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:008 (openssh).


A problem in the handling of scp in openssh could be used to execute
commands on remote hosts even using a scp-only configuration.

This requires doing a remote-remote scp and a hostile server. (CVE-2006-0225)

On SUSE Linux Enterprise Server 9 the xauth pollution problem was fixed too.

The security fix changes the handling of quoting filenames which might
break automated scripts using this functionality.

Please check that your automated scp scripts still work after the
update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_08_openssh.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/15");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssh package";
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
if ( rpm_check( reference:"openssh-4.1p1-10.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.1p1-10.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-4.1p1-11.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.1p1-11.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-12.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-12.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
