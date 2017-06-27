# @DEPRECATED@
#
# This script has been deprecated as the VuXML entry has been 
# cancelled.
#
# Disabled on 2011/10/02.

#
# (C) Tenable Network Security
#
#
if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14281);
 script_bugtraq_id(10149);
 script_cve_id("CVE-2004-0157");
 script_version ("$Revision: 1.11 $");

 name["english"] = "FreeBSD Xonix vulnerability";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is running an older version of Xonix.

Xonix is a game.

This version of Xonix calls an external program while retaining
setgid privileges.  An attacker, exploiting this flaw, would need
local access.  A successful attack would give the attacker the
privileges of the 'games' group." );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/6fd9a1e9-efd3-11d8-9837-000c41e2cdad.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_cvs_date("$Date: 2011/10/03 01:28:59 $");
 script_end_attributes();

 
 summary["english"] = "FreeBSD Xonix local exploit";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}


exit(0, "This plugin has been deprecated as the associated VuXML entry has been cancelled.");

include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");
package = egrep(pattern:"^xonix-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"xonix-1.4_1") < 0 )
        security_warning(0);



