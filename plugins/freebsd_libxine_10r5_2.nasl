# @DEPRECATED@
#
# This script has been deprecated as the VuXML entry has been
# superseded by VuXML entry b6939d5b-64a1-11d9-9106-000a95bc6fae.
#

#
# (C) Tenable Network Security
#
#

exit(0);
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14351);
 script_bugtraq_id(10890);
 script_version ("$Revision: 1.10 $");
 name["english"] = "FreeBSD Ports: libxine < 1.0r5_2";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of libxine installed.

libxine is a set of libraries for the Xine multimedia player. There is a buffer
overflow condition in the remote version of this library which may allow
an attacker to execute arbitrary code on the remote host when a libxine-enabled
application processes a malformed vcd:// input source indentifier.

To exploit this flaw, an attacker would need to send a malicious playlist file
to a Xine user on the remote host, containing a malformed vcd:// link." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/bef4515b-eaa9-11d8-9440-000347a4fa7d.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/23");
 script_cvs_date("$Date: 2011/10/03 01:28:59 $");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the libxine package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

exit(0, "This plugin has been deprecated as the associated VuXML entry has been superseded.");


include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = egrep(pattern:"^libxine-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"libxine-1.0.r5_2") < 0 ) security_hole(0);
