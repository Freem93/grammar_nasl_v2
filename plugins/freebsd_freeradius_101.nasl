#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15500);
 script_version ("$Revision: 1.5 $");
 name["english"] = "FreeBSD Ports : FreeRADIUS < 1.0.1";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has the following package installed :
	0.8.0 <= freeradius < 1.0.1


The remote version of this software is vulnerable to a flaw which may allow
an attacker to disable this service remotely." );
 script_set_attribute(attribute:"solution", value:
"Update the package on the remote host" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the freeradius package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");
if ( ! pkgs ) exit(0);

package = egrep(pattern:"^freeradius-[0-9]", string:pkgs);
if (package &&
    pkg_cmp(pkg:package, reference:"freeradius-0.8.0") >= 0 &&
    pkg_cmp(pkg:package, reference:"freeradius-1.0.1") <= 0 ) 
	{
	security_warning(0);
	exit(0);
	}
