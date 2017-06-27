#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10407);
  script_version ("$Revision: 1.37 $");
  script_cvs_date("$Date: 2013/01/25 01:19:11 $");

  name["english"] = "X Server Detection";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"An X11 server is listening on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host is running an X11 server.  X11 is a client-server
protocol that can be used to display graphical applications running on
a given host on a remote client. 

Since the X11 traffic is not ciphered, it is possible for an attacker
to eavesdrop on the connection." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to this port. If the X11 client/server facility is not
used, disable TCP support in X11 entirely (-nolisten tcp)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "X11 detection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


function x11_request(socket)
{
 local_var req, r, len;

 req = raw_string(
	0x6c,		# Little-Endian
	0x00,		# Unused
	0x0b, 0x00,	# Protocol Major Version
	0x00, 0x00,	# Protocol Minir Version
	0x00, 0x00,	# Authorization protocol name length
	0x00, 0x00,	# Authorization protocol data length
	0x00, 0x00);	# Unused


 send(socket:socket, data:req);
 
 r = recv(socket:socket, length:8);
 if ( strlen(r) != 8 ) return NULL;

 len = substr(r, 6, 7);
 len = ord(len[0]) + ord(len[1]) * 256;
 r += recv(socket:socket, length:len, min:len);
 if ( strlen(r) != len + 8 ) return NULL;
 return r;
}

function x11_open(blob)
{
 local_var ret;

 if ( ! blob ) return NULL;
 return ord(blob[0]);
}

function x11_version(blob)
{
 local_var ret, vers;

 if ( strlen(blob) <= 8 ) return NULL;
 vers = ord(blob[2]) + ord(blob[3]) * 256;
 if ( vers <= 0 || vers > 11 ) return NULL; # Not X11
 ret = string(vers);
 vers = ord(blob[4]) + ord(blob[5]) * 256;
 ret += "." + vers;
 return ret;
}

function x11_release(blob)
{
 local_var ret;

 if ( strlen(blob) <= 11 ) return NULL;
 ret = substr(blob, 8, 11);
 ret = ord(ret[0]) + (ord(ret[1]) << 8) + (ord(ret[2]) << 16) + (ord(ret[3]) << 24);
 return ret;
}



function x11_vendor(blob)
{
 local_var len;

 if ( strlen(blob) < 25 ) return NULL;

 len = substr(blob, 24, 25);
 len = ord(len[0]) + ord(len[1]) * 256;
 if ( len >= strlen(blob) ) return NULL;
 return substr(blob, 40, 40 + len - 1);
}


function select(num, sockets, timeout)
{
 local_var flag, e, then, soc, i, ret;

 if ( ! defined_func("socket_ready") ) return sockets;

 then = unixtime();
 flag = 0;
 for ( i = 0 ; i < num ; i ++ ) ret[i] = 0;

 while ( TRUE )
 {
   flag = 0;
   for ( i = 0 ; i < num ; i ++ ) 
   {
    if ( sockets[i] != 0 )
	{
	 e = socket_ready(sockets[i]);
	 if ( e < 0 ) {
	 	close(sockets[i]);
		sockets[i] = 0;
		}
	 else if ( e > 0 ) {
	 	 ret[i] = sockets[i];
		 sockets[i] = 0;
		}
	 else flag ++;
	}
   }
   if ( unixtime() - then >= timeout ) return ret;
   if ( flag != 0 ) sleep(1);
   else break;
 }

 return ret;
}

for ( i = 0 ; i < 10 ; i ++ )
 {
  if ( get_port_state(6000 + i ) )
	{
	 if ( func_has_arg("open_sock_tcp", "nonblocking") )
  		sockets[i] = open_sock_tcp(6000 + i, nonblocking:TRUE);
	 else
  		sockets[i] = open_sock_tcp(6000 + i);
	}
  else
	sockets[i] = 0;
}


if ( NASL_LEVEL >= 3000 ) sockets = select(num:10, sockets:sockets, timeout:5);

for ( i = 0 ; i < 10 ; i ++ )
{
 soc = sockets[i];
 if ( soc != 0 )
 {
 report = NULL;
 blob = x11_request(socket:soc);
 close(soc);
 if ( ! blob ) continue;
 open = x11_open(blob:blob);
 version = x11_version(blob:blob);
 if ( version == NULL ) continue; # Not X11
 if ( open )
 {
  release = x11_release(blob:blob);
  vendor  = x11_vendor(blob:blob);
 }
 port = 6000 + i;
 if ( open == 1 ) set_kb_item(name:"x11/" + port + "/open", value:open);
 if ( version ) set_kb_item(name:"x11/" + port + "/version", value:version);
 if ( release ) set_kb_item(name:"x11/" + port + "/release", value:release);
 if ( vendor  ) set_kb_item(name:"x11/" + port + "/vendor", value:vendor);
 report = '\nX11 Version : ' + version + '\n';
 if ( open )
 {
  report += 'X11 Release : ' + release + '\n';
  report += 'X11 Vendor  : ' + vendor  + '\n';
 }
 security_note(port:port, extra:report);
 register_service(port:port, proto:'x11');
 }
}

