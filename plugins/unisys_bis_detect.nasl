#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(42843);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"Unisys Business Information Server Detection");
  script_summary(english:"Detects Unisys Mapper Server");

  script_set_attribute(attribute:"synopsis", value:
"An information server is running on the remote host." );

  script_set_attribute(attribute:"description", value:
"Unisys Business Information Server (BIS), a highly scalable,
multimode, enterprise-level, rapid-application development and
information access tool, is listening on the remote host." );

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d9673df");

  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );

  script_set_attribute(attribute:"risk_factor", value:
"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");	
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");		
  script_require_ports(3986,"Services/unknown");
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(3986);
  if (!port ) exit(0, "Service listening on port "+ port + " is not unknown.");
  if (!silent_service(port)) exit(0, "Service listening on port "+ port + " is not a silent service.");
}
else port = 3986;

if (known_service(port:port)) exit(0,"Service listening on port "+ port + " is already known." );
if (!get_tcp_port_state(port)) exit(1," Port "+ port + " is not open." );

soc = open_sock_tcp(port);
if (!soc) exit(1, "Could not open socket on port "+ port +".");

send(socket:soc, data:"A");
res = recv(socket:soc, min: 0, length:1024);
if(!res)
{
  close(soc);
  exit(0, "The service on port "+port+" did not respond to the first request.");
}


if(res == ">")
{
  req = string("Mapper.exe fd -sA");
  send(socket:soc, data:req);
  res = recv(socket:soc, min:12, length:1024);
  if (strlen(res) != 12)
  {
    exit(0, "The service on port "+port+" did not reply as expected.");
    close(soc);
  }  

  session_id = substr(res,2,5); 
  if (raw_string(0x03,0x30,session_id,0x20,0x30,session_id) == res)
  {
    register_service(port:port, ipproto:"tcp", proto:"unisys-bis");
    security_note(port);
  }
  close(soc);
}
else
{
  close(soc);
  exit(0, "The service listening on port "+port+" does not appear to be a BIS server.");
}
