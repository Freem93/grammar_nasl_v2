#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42933);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/29 03:07:54 $");

  script_name(english:"Squeezebox Server Detection");
  script_summary(english:"Sends a HELO message");

  script_set_attribute(
    attribute:"synopsis", 
    value:"A streaming audio service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is used by Squeezebox Server (formerly known as
SlimServer and SqueezeCenter) to communicate with associated
streaming audio players."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wiki.slimdevices.com/index.php/SlimProtoTCPProtocol"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's 
acceptable use and security policies."
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/30"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3483);

  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(3483);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 3483;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a 'HELO'.
macaddr = get_local_mac_addr();
helo_data = mkbyte(3) +                # device id
  mkbyte(1) +                          # firmware revision
  macaddr;                             # MAC addr
req = 'HELO' +
  mkdword(strlen(helo_data)) +
  helo_data;
send(socket:soc, data:req);
res_1 = recv(socket:soc, length:2, min:2);
if (strlen(res_1) != 2) exit(1, "Service on port "+port+" failed to send packet length.");
len = getword(blob:res_1, pos:0);
res_2 = recv(socket:soc, length:len, min:len);
if (strlen(res_2) != len) exit(1, "Service on port "+port+" failed to send remaining "+len+" bytes.");
res = res_1 + res_2;
if (!strlen(res)) exit(0);


# If it looks like a valid reply.
if (ereg(pattern:"^vers[0-9].+", string:res_2))
{
  # Register and report the service.
  register_service(port:port, proto:"squeeze_slimproto");

  info = "";
  if (report_verbosity > 1)
  {
    # Collect version info.
    ver = str_replace(find:"vers", replace:"", string:res_2);
    info += '  Version : ' + ver + '\n';
  }

  if (info)
  {
    report = '\n' +
      'Nessus collected the following information from the remote service :\n' +
      '\n' +
      info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

# Disconnect.
req = 'BYE!' + mkdword(0);
send(socket:soc, data:req);
res = recv_line(socket:soc, length:256);
close(soc);
