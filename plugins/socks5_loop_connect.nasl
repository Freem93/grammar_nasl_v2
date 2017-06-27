#
# (C) Tenable Network Security, Inc.
#

# Socks5 is defined by those RFC:
# RFC1928 SOCKS Protocol Version 5
# RFC1929 Username/Password Authentication for SOCKS V5
# RFC1961 GSS-API Authentication Method for SOCKS Version 5
#

include( 'compat.inc' );

if(description)
{
  script_id(17156);
  script_version ("$Revision: 1.11 $");
  script_osvdb_id(56284);
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_name(english:"SOCKS5 Server Recursive Connection Remote DoS");
  script_summary(english:"Connect back to SOCKS5 proxy");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote proxy is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'It was possible to connect to the SOCKS5 server through itself.

This allows anybody to saturate the proxy CPU, memory or
file descriptors.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Reconfigure your proxy so that it refuses connections to itself.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(
    attribute:'see_also',
    value:'http://tools.ietf.org/html/rfc1928'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_require_ports("Services/socks5", 1080);
  script_dependencie("find_service1.nasl", "find_service2.nasl");
  exit(0);
}

#

# include("dump.inc");

port = get_kb_item("Services/socks5");
if (! port) port = 1080;
if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);

req5 = raw_string(5, 3, 0, 1, 2);
send(socket: s, data: req5);
data = recv(socket: s, length: 2);

p2 = port % 256;
p1 = port / 256;
a = split(get_host_ip(), sep: '.');

cmd =
raw_string(5, 1, 0, 1, int(a[0]), int(a[1]), int(a[2]), int(a[3]), p1, p2);

for (i = 3; i >= 0; i --)
{
  send(socket: s, data: cmd);
  data = recv(socket: s, length: 10, min: 10);
# dump(ddata: data, dtitle: "socks");
  if (strlen(data) != 10 || ord(data[0]) != 5 || ord(data[1]) != 0) break;
}

close(s);
if (i < 0) security_warning(port);
