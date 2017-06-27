# @DEPRECATED@
#
# This script has been deprecated as the VuXML entry has been
# superseded by VuXML entry 9be819c6-4633-11d9-a9e7-0001020eed82.
#
# Disabled on 2010/10/06.

#
# (C) Tenable Network Security
#
# The plugin description is (C) Jacques Vidrine and contributors. 
#
#

exit(0);
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15798);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id ( 11355 );
 name["english"] = "FreeBSD Ports : bnc <= 2.8.9";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has one of the following packages installed :

bnc <= 2.8.9

The function getnickuserhost() suffers from a buffer-overflow.  It is called 
when BNC processes a response from IRC server.  An attacking server can use 
this vulnerability to gain shell  access, on the BNC running machine." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/1f8dea68-3436-11d9-952f-000c6e8f12ef.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/23");
 script_cvs_date("$Date: 2011/10/02 00:59:38 $");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the bnc package";
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

package = egrep(pattern:"^bnc-[012]\.", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"bnc-2.8.9") <= 0  )
	{
	security_hole(0);
	exit(0);
	}
