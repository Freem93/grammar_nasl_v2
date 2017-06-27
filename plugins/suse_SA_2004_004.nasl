#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:004
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13822);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SuSE-SA:2004:004: gaim";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:004 (gaim).


Gaim is a multi-protocol instant-messaging client. Stefan Esser found
12 vulnerabilities in gaim that can lead to a remote system compromise
with the privileges of the user running GAIM.
The GAIM package that SUSE LINUX ships is affected by just two of these
bug:
- Yahoo Packet Parser Overflow
- HTTP Proxy Connect Overflow

The first vulnerability is easy to exploit and results in a classic stack
overflow which can be used to execute arbitrary code.
The latter vulnerability requires the gaim client use a HTTP proxy under
the control of the attacker. The exploitation of this bug results in
arbitrary code execution too.

There is no known workaround.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, to apply the update use the command 'rpm -Fhv file.rpm'." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_04_gaim.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the gaim package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gaim-0.50-187", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-0.59-158", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-0.59.8-60", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-0.67-65", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
