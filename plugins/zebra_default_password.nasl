#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(16205);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");

 script_bugtraq_id(10935);
 script_osvdb_id(9074);

 script_name(english:"Default Password (zebra) for Zebra");
 script_summary(english:"Logs into the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote router is protected with a default password.");
 script_set_attribute(attribute:"description",  value:
"The remote host is running Zebra, a routing daemon.

The remote Zebra installation uses as its password the default,
'zebra'.  An attacker may log in using this password and control the
routing tables of the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/184");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/205");
 script_set_attribute(attribute:"solution", value:"Edit 'zebra.conf' and set a strong password.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_family(english:"Firewalls");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service2.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/zebra", 2601);
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

port = get_kb_item("Services/zebra");
if ( ! port ) port = 2601;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"Password: ");
if ( ! res ) exit(0);

send(socket:soc, data:'zebra\r\n'); # Default password
res = recv_until(socket:soc, pattern:"> "); # Wait for the cmd prompt
send(socket:soc, data:'list\r\n'); # Issue a 'list' command
res = recv(socket:soc, length:4096);
if ( "show memory" >< res )
	security_hole(port);
