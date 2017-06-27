#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14376);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(11041);
 script_osvdb_id(9166);
 
 script_name(english:"ignitionServer SERVER Command Spoofed Server Saturation DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the IgnitionServer IRC 
service that could be vulnerable to a denial of service in the SERVER
command.

An attacker could crash the remote host by misusing the SERVER command
repeatdly." );
 script_set_attribute(attribute:"see_also", value:"http://www.ignition-project.com/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IgnitionServer 0.3.2 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/22");
 script_cvs_date("$Date: 2011/12/14 21:54:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([0-2]\.|3\.[01][^0-9]).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}

