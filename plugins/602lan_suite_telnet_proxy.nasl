#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18208);
  script_version("$Revision: 1.11 $");

  script_name(english:"602LAN SUITE Open Telnet Proxy");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an open Telnet proxy server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running 602LAN SUITE with an open Telnet server
proxy.  By using through such a proxy, an attacker may be able to launch
attacks that appear to originate from the remote host and possibly to
access resources that are only available to machines on the same
internal network as the remote host." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure 602LAN SUITE, disabling the TELNET server proxy." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/09");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for telnet proxy in 602LAN SUITE");
  script_category(ACT_ATTACK);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_port_state(port)) exit(0, "TCP port "+port+" is closed.");


# Open a connection and grab the banner.
soc = open_sock_tcp(port);
if (!soc) exit(1, "TCP connection failed to port "+port+".");
banner = recv(socket:soc, length:2048);

# If it looks like 602LAN SUITE...
if ("host[:port]:" >< banner) {
  # Try to connect back to the server on port 31337.
  req = string(this_host(),":31337\r\n");
  filter = string("tcp and src ", get_host_ip(), " and dst ", this_host(), " and dst port 31337");
  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:2048);

  # Hmmm, there seems to be a filter limiting outbound connections.
  if ("Access Denied by IP Filter" >< res)
    exit(0, "Outbound connections are filtered (port=", port, ").");

  # If we can, there's a problem.
  res = pcap_next(pcap_filter:filter);
  if (res) security_warning(port);
}
