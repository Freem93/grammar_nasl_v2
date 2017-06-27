#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35081);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/10/16 17:51:58 $");

 script_name(english:"Xen Guest Detection");
 script_summary(english:"Determines if the remote host is Xen.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a Xen virtual machine.");
 script_set_attribute(attribute:"description", value:
"According to the MAC address of its network adapter, the remote host
is a Xen virtual machine.");
 script_set_attribute(attribute:"solution", value:
"Ensure that the host's configuration is in agreement with your
organization's security policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

 script_dependencies("report_hw_macs.nasl");
 exit(0);
}

ether = get_kb_item("Host/mac_addrs");
if ( ! ether ) exit(0);
# -> http://standards.ieee.org/regauth/oui/index.shtml
# http://wiki.xensource.com/xenwiki/XenNetworking
if ( egrep(pattern:"^00:16:3e", string:tolower(ether)) ) security_note(0);
