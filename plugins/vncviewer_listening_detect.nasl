#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30150);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/12/06 22:24:38 $");

  script_name(english:"VNCviewer in Listen Mode Detection");
  script_summary(english:"Tries to initiate a connection to a client");

 script_set_attribute(attribute:"synopsis", value:
"A remote control service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a VNC viewer in listen mode, allowing VNC
servers to initiate reverse connections back to the client running on
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec9f0272" );
 script_set_attribute(attribute:"see_also", value:"http://gentoo-wiki.com/VNC#Reverse_VNC" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5500);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(5500);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 5500;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Initiate protocol negotiation.
req = 'RFB 003.008\n';
send(socket:soc, data:req);

# If the response looks right...
res = recv(socket:soc, length:12, min:12);
if (
  strlen(res) == 12 &&
  res =~ '^RFB [0-9]{3}\\.[0-9]{3}\n'
)
{
  # Extract the protocol version.
  res = chomp(res);
  proto = res - "RFB ";
  ver = split(proto, sep:".", keep:FALSE);
  ver_maj = int(ver[0]);
  ver_min = int(ver[1]);

  if (ver_maj == 3 && (ver_min == 4 || ver_min == 6)) 
  {
    info = '  3.' + ver_min + ' (possibly UltraVNC)\n';
  }
  else if (ver_maj == 3 && ver_min == 5) 
  {
    info = '  3.5 (possibly TightVNC)\n';
  }
  else if (ver_maj == 3) 
  {
    info = '  3.' + ver_min + '\n';
  }
  else
  {
    if (report_paranoia < 2) exit(0, "client sent an odd protocol response (res)");
    else info = '  ' + ver_maj + '.' + ver_min + ' (probably an invalid protocol)\n';
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"vncviewer");

  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote VNC client prefers the following protocol :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  } else security_note(port);
}
close(soc);
