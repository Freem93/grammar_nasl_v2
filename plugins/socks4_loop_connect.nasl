#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
 script_id(17155);
 script_version ("$Revision: 1.11 $");
 script_osvdb_id(56284);

 script_name(english:"SOCKS4 Server Recursive Connection Remote DoS");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SOCKS service is prone to a denial of service attack."
 );
 script_set_attribute(attribute:"description", value:
"It is possible to connect to the SOCKS4 server through itself.  An
attacker can leverage this issue to saturate the host's CPU, memory or
file descriptors." );
 script_set_attribute(
  attribute:"solution", 
  value:"Reconfigure the service so that it refuses connections to itself."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/20");
 script_cvs_date("$Date: 2012/09/27 21:23:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Connect back to SOCKS4 proxy");
 
 script_category(ACT_ATTACK);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 exit(0);
}

#

# include("dump.inc");

port = get_kb_item("Services/socks4");
if (! port) port = 1080;
if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);

p2 = port % 256;
p1 = port / 256;
a = split(get_host_ip(), sep: '.');


cmd = raw_string(4, 1, p1, p2, int(a[0]), int(a[1]), int(a[2]), int(a[3]))
	+ "root" + '\0';
for (i = 3; i >= 0; i --)
{
  send(socket: s, data: cmd);
  data = recv(socket: s, length: 8, min: 8);
  # dump(ddata: data, dtitle: "socks");
  if (strlen(data) != 8 || ord(data[0]) != 4 || ord(data[1]) != 90) break;
}

close(s);
if (i < 0) security_hole(port);
