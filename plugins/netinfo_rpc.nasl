#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11899);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"RPC nibindd Service Detection");
  script_summary(english:"Connects to the remote nibindd RPC service");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"This script determines whether or not the nibindd rpc service is running,
in which case it connects to it to extract the list of NetInfo
domains the remote host is serving."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Restrict access to NetInfo."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  script_dependencies("rpc_portmap.nasl");
  exit(0);
}

RPC_PROG = 200100000;

function get_rpc_port(protocol, program)
{
 local_var	broken, req, soc, r, port;
 local_var	a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;



 a = rand() % 255;
 b = rand() % 255;
 c = rand() % 255;
 d = rand() % 255;

 p_a = program / 16777216; 	p_a = p_a % 256;
 p_b = program / 65356; 	p_b = p_b % 256;
 p_c = program / 256;   	p_c = p_c % 256;
 p_d = program % 256;

 pt_a = protocol / 16777216; pt_a = pt_a % 256;
 pt_b = protocol / 65535   ; pt_b = pt_b % 256;
 pt_c = protocol / 256;    ; pt_c = pt_c % 256;
 pt_d = protocol % 256;


 req = raw_string(a, 	b, 	c, 	d, 	# XID
 		  0x00, 0x00, 0x00, 0x00,	# Msg type: call
		  0x00, 0x00, 0x00, 0x02,	# RPC Version
		  0x00, 0x01, 0x86, 0xA0,	# Program
		  0x00, 0x00, 0x00, 0x02,	# Program version
		  0x00, 0x00, 0x00, 0x03,	# Procedure
		  0x00, 0x00, 0x00, 0x00,	# Credentials - flavor
		  0x00, 0x00, 0x00, 0x00, 	# Credentials - length
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Flavor
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Length

		  0x0b, 0xed, 0x48, 0xa1,	# Program
		  0xFF, 0xFF, 0xFF, 0xFF,	# Version (any)
		  pt_a, pt_b, pt_c, pt_d,	# Proto (udp)
		  0x00, 0x00, 0x00, 0x00	# Port
 		  );


  port = int(get_kb_item("rpc/portmap"));
  if(port == 0)port = 111;


 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if(broken)return(0);

if (! get_udp_port_state(port)) return 0;
 soc = open_sock_udp(port);
 if ( ! soc ) return 0;
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);

 close(soc);
 if(!r)
 {
  set_kb_item(name:string("/tmp/rpc/noportmap/", port), value:TRUE);
  return(0);
 }

 if(strlen(r) < 28)
  return(0);
 else
  {
   p_d = ord(r[27]);
   p_c = ord(r[26]);
   p_b = ord(r[25]);
   p_a = ord(r[24]);
   port = p_a;
   port = port * 256;
   port = port +p_b;
   port = port * 256;
   port = port + p_c;
   port = port * 256;
   port = port + p_d;
   return(port);
  }
}





function netinfo_recv(socket)
{
 local_var buf, len;

 buf = recv(socket:socket, length:4);
 if(strlen(buf) < 4)return NULL;

 len = ord(buf[3]) + ord(buf[2])*256;

 buf += recv(socket:socket, length:len);
 return buf;
}




rpcport = get_rpc_port(protocol:IPPROTO_TCP, program:RPC_PROG);
if ( !rpcport ) exit(0);
if ( !get_port_state(rpcport)) exit(0);

soc = open_sock_tcp(rpcport);
if ( ! soc ) exit(0);

req = raw_string(0x80, 0x00, 0x00, 0x28, 0x11, 0xe0, 0x40, 0x95,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa1, 0x00, 0x00, 0x00, 0x01,
		 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
r = netinfo_recv(socket:soc);
close(soc);
if(strlen(r) < 35)exit(0);

num_domains = ord(r[35]);
start = 38;

report = "";
for ( i = 0 ; i < num_domains ; i ++ )
{
 len = ord(r[start]) * 256 + ord(r[start+1]);
 start += 2;
 report += '\n . ' + substr(r, start, start + len - 1);
 start += len;
 if(len % 4)start += 4 - (len % 4);
 start += 2;
 udp = ord(r[start]) * 256 + ord(r[start+1]);
 start += 4;
 tcp = ord(r[start]) * 256 + ord(r[start+1]);
 report += ' (serving on tcp port ' + tcp + ' and udp port ' + udp + ')';
 start += 4;
}


if ( strlen(report) )
{
 report = "
The remote host is running the nibindd RPC service, which implies that it
is a NetInfo server (so it is probably running MacOS X or NeXT). It serves
the following list of domains :
" + report +
"

An attacker might use this information to gather the relevant
maps from the remote system, like the password file or the configuration
of the domain.

Solution : filter incoming traffic to this port. If the remote host is not a
NetInfo server, kill the 'nibindd' service.
Risk factor : Medium";

 security_warning(port:rpcport, extra:report);
}
