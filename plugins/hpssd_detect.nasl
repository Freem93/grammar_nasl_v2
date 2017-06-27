#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27056);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/29 21:03:42 $");

  script_name(english:"HP Linux Imaging and Printing System HPSSD Daemon Detection");
  script_summary(english:"Sends a queryhistory request");

 script_set_attribute(attribute:"synopsis", value:
"A printing service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an hpssd daemon, a component of the HP Linux
Imaging and Printing (HPLIP) System that provides various services to
HPLIP client applications." );
 script_set_attribute(attribute:"see_also", value:"http://hplip.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:linux_imaging_and_printing_project");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 2207);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(2207);
  if (!port) exit(0);
}
else port = 2207;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Query history of a device-uri.
uri = "hp:/net/deskjet_5800?ip=127.0.0.1";

req = string(
  "device-uri=", uri, "\n",
  "msg=queryhistory\n"
);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:22);
close(soc);


# Register and report the service if we see a valid result.
if (strlen(res) && "msg=queryhistoryresult" >< res)
{
  register_service(port:port, proto:"hpssd");
  security_note(port);
}
