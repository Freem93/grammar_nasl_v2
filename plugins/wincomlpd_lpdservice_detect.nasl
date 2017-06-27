#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30185);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"WinComLPD LPD Monitoring Server Detection");
  script_summary(english:"Tries to authenticate to LPDService");

 script_set_attribute(attribute:"synopsis", value:
"A printer control service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is the LPD Monitoring Server port used for remote
print queue management by WinComLPD Total, a commercial Line Printer
Daemon application for Windows." );
 script_set_attribute(attribute:"see_also", value:"http://clientsoftware.com.au/lpd.html" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 13500);

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
  port = get_unknown_svc(13500);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 13500;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send an authentication packet.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cmd = 0x03e9;
user = "nessus";
pass = string(unixtime());
domain = "";

req = 
  mkdword(1) + 
  mkdword(2) +
  mkbyte(strlen(user)) + user +
  mkbyte(strlen(pass)) + pass +
  mkbyte(strlen(domain)) + domain +
  mkbyte(5) + mkbyte(4) +
  mkword(0);
req = 
  mkdword(0) +
  mkword(0) + 
  mkword(cmd) +
  mkword(0) +
  mkword(strlen(req)) + req;

filter = string("udp and src ", get_host_ip(), " and dst port 0");
debug_pkt = send_capture(socket:soc, data:req, pcap_filter:filter);

if (!isnull(debug_pkt)) 
{
  debug_msg = get_udp_element(udp:debug_pkt, element:"data");
  if ("LPDAdmin Client " >!< debug_msg) debug_msg = "";
}
else debug_msg = "";

res = recv(socket:soc, length:12, min:4);
close(soc);


# If the response looks right...
if (
  strlen(res) == 12 &&
  getword(blob:res, pos:6) == (0x8000 + cmd) &&
  (
    (debug_msg && " access failed" >< debug_msg) ||
    (
      (
        getword(blob:res, pos:8) == 0x7d2 ||
        getword(blob:res, pos:8) == 0x7dd
      ) &&
      getword(blob:res, pos:10) == 0
    )
  )
)
{
  # Register and report the service(s).
  register_service(port:port, proto:"lpdservice");
  security_note(port);

  if (debug_msg)
  {
    udp_port = get_udp_element(udp:debug_pkt, element:"uh_sport");
    register_service(port:udp_port, ipproto:"udp", proto:"lpdservice_debug");
    # security_note moved to wincomlpd_debug.nasl
  }
}
