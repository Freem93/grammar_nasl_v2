#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(41028);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-1999-0517");
 script_bugtraq_id(2112);
 script_xref(name:"OSVDB", value:"209");

 script_name(english:"SNMP Agent Default Community Name (public)");
 script_summary(english:"Checks if the SNMP Agent supports the community name 'public'");

 script_set_attribute(
  attribute:"synopsis",
  value:"The community name of the remote SNMP server can be guessed."
 );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the default community name of the remote
SNMP server.

An attacker may use this information to gain more knowledge about the
remote host, or to change the configuration of the remote system (if
the default community allows such modifications)." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it.
Either filter incoming UDP packets going to this port, or change the 
default community string." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/25"
 );
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/11/17");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");

 script_dependencies("snmp_default_communities.nasl");
 exit(0);
}


port = get_kb_item("SNMP/port");
if (!port) port = 161;


default = get_kb_item("SNMP/community");
if ( default != "public" )
{
 default = get_kb_list("SNMP/default/community");
 if (isnull(default)) exit(0, "The 'SNMP/default/community' KB item is missing.");
 default = make_list(default);
 if (max_index(default) > 1) exit(0, max_index(default)+" default communities were found.");
 comm_list = strcat('  - ', default[0], '\n');
}
else 
  comm_list = default;

if ("public" >< comm_list)
{
  report = string(
    "\n",
    "The remote SNMP server replies to the following default community\n",
    "string :\n",
    "\n",
    comm_list
  );
  security_hole(port:port, extra:report, protocol:"udp");
}
else exit(0, "The default SNMP community is '"+comm_list+"' rather than 'public'.");
