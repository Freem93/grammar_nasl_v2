# @DEPRECATED@
# 
# This script has been deprecated by freebsd_pkg_c480eb5e7f0011d8868e000347dd607f.nasl.
#
# Disabled on 2011/10/01.


#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12592);
 script_bugtraq_id(9942);
 script_version ("$Revision: 1.10 $");
 name["english"] = "FreeBSD Ports: phpBB < 2.0.8";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host has an old version of phpBB installed.

phpBB is a PHP-based bulletin board. There is a cross-site
scripting issue in the remote version of this software which 
may allow an attacker to damage the remote phpBB installation" );
 script_set_attribute(attribute:"solution", value:
"http://www.vuxml.org/freebsd/c480eb5e-7f00-11d8-868e-000347dd607f.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_cvs_date("$Date: 2011/10/02 01:05:36 $");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the phpbb package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}


exit(0, "This plugin has been deprecated. Refer to plugin #37811 (freebsd_pkg_c480eb5e7f0011d8868e000347dd607f.nasl) instead.");

include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");

package = egrep(pattern:"^phpbb-", string:pkgs);
if ( pkg_cmp(pkg:package, reference:"phpbb-2.0.8") < 0 ) 
	security_warning(0);
