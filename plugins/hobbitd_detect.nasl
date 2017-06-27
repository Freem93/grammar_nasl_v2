#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22180);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Hobbit Monitor Daemon Detection");
  script_summary(english:"Detects a Hobbit Monitor daemon");

 script_set_attribute(attribute:"synopsis", value:
"A Hobbit server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the server component of Hobbit Monitor, an
open source application and network monitoring tool." );
 script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/projects/hobbitmon/" );
 script_set_attribute(attribute:"solution", value:
"Consider restricting access to this service to the localhost, which is
the default configuration." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:hobbit_monitor:hobbit_monitor");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1984);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(1984);
  if (!port) exit(0);
}
else port = 1984;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a request for a config file.
file = "hobbitserver.cfg";
filter = string("tcp and src ", get_host_ip(), " and src port ", port);
res = send_capture(socket:soc, data:string("config ", file), pcap_filter:filter);
if (res == NULL) exit(0);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0);


# Half-close the connection so the server will send the results.
ip = ip();
seq = get_tcp_element(tcp:res, element:"th_ack");
tcp = tcp(
  th_dport : port,
  th_sport : get_source_port(soc),
  th_seq   : seq,
  th_ack   : seq,
  th_win   : get_tcp_element(tcp:res, element:"th_win"),
  th_flags : TH_FIN|TH_ACK
);
halfclose = mkpacket(ip, tcp);
send_packet(halfclose, pcap_active:FALSE);
res = recv(socket:soc, length:65535);
if (res == NULL) exit(0);


# It's a hobbit server if the result looks like a config file.
if (egrep(pattern:'^ *(HOBBITCLIENTHOME|HOBBITLOGO|USEHOBBITD) *=', string:res))
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"hobbitd");

  report = string(
    "Here are the contents of hobbitd's ", file, " that Nessus was\n",
    "able to retrieve from the remote host :\n",
    "\n",
    res
  );

  security_note(port:port, extra:report);
}
