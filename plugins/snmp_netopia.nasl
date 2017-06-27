#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(22415);
 script_version("$Revision: 1.13 $");
 script_osvdb_id(58635);
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");

 script_name(english:"Netopia Router Crafted SNMP Request Remote Admin Password Disclosure");
 script_summary(english:"Checks to see if the router will disclose the admin password");
 script_set_attribute(attribute:"synopsis", value:
"The remote router allows anonymous users to retrieve the administrative password" );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a Netopia router with SNMP enabled.
Further, the Netopia router is using the default SNMP community strings.
This version of the Netopia firmware is vulnerable to a flaw wherein
a remote attacker can, by sending a specially formed SNMP query, retrieve
the Administrative password.

An attacker, exploiting this flaw, would only need to be able to send SNMP
queries to the router using the default community string of 'public'.
Successful exploitation would result in the attacker gaining administrative
credentials to the router." );
 script_set_attribute(attribute:"see_also", value:"http://www.netopia.com/" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch.  Change the default SNMP community string to
one that is not easily guessed." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_dependencie("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

password = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.304.1.3.1.23.1.0");

if(strlen(password))
{
 report = string ("The administrator password is '", password, "'.");

 security_hole(port:port, extra:report, protocol:"udp");
}
