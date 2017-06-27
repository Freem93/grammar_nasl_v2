#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11716);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");

 script_name(english:"Gnutella Root Directory Misconfiguration");
 script_summary(english:"Detect sensitive files shared by Gnutella");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a P2P application that is misconfigured." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gnutella servent service.

It seems that the root directory of the remote host is visible through 
this service. Confidential files might be exported." );
 script_set_attribute(attribute:"solution", value:
"Disable this Gnutella servent or configure it correctly." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_dependencie("find_service1.nasl", "gnutella_detect.nasl");
 script_require_ports("Services/gnutella", 6346);
 exit(0);
}

#

function gnutella_read_data(socket, message)
{
  local_var	len, i, r2;
  len = 0;
  for (i = 22; i >= 19; i --)
    len = len * 256 + ord(message[i]);
  if (len > 0)
    r2 = recv(socket: socket, length: len);
  return r2;
}

function gnutella_search(socket, search)
{
  local_var	MsgId, Msg, r1, r2;

  MsgId = rand_str(length: 16);
  Msg = raw_string(	MsgId,			# Message ID
			128,			# Function ID
			1,			# TTL
			0,			# Hops taken
			strlen(search)+3, 0, 
			0, 0,			# Data length (little endian)
			0, 0,			# Minimum speed (LE)
			search, 0);
  send(socket: socket, data: Msg);

# We might get Ping and many other Gnutella-net messages
# We just read and drop them, until we get our answer.
  while (1)
  {
    r1 = recv(socket: socket, length: 23);
    if (strlen(r1) < 23)
      return NULL;
    r2 = gnutella_read_data(socket: socket, message: r1);
    if (ord(r1[16]) == 129 && substr(r1, 0, 15) == MsgId)
      return r2;
  }
}

#

include("misc_func.inc");

port = get_kb_item("Services/gnutella");
if (! port) port = 6346;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket:soc, data: 'GNUTELLA CONNECT/0.4\n\n');
r = recv(socket: soc, length: 13);
if (r != 'GNUTELLA OK\n\n')
{
  close(soc);
  exit(0);
}

# GTK-Gnutella sends a ping on connection
r = recv(socket: soc, length: 23);
if (strlen(r) >= 23)
{
  r2 = gnutella_read_data(socket: soc, message: r);
  if (ord(r[16]) == 0)	# Ping
  {
    # Pong  (phony answer)
    MsgId = substr(r, 0, 15);
    ip = this_host();
    #display("ip=", ip, "\n");
    x = eregmatch(string: ip, pattern: "([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)");
    #display("ip=", x, "\n");
    Msg = raw_string(	MsgId,
			1,	# pong
			1,	# TTL
			0,	# Hop
			14, 0, 0, 0, 
			11, 11,			# Listening port
			int(x[1]), int(x[2]), int(x[3]), int(x[4]),	# IP
			1, 1, 0, 0, 	# File count (little endian)
			1, 1, 0, 0);	# KB count
   send(socket: soc, data: Msg);
  }
}

dangerous_file = 
	make_list("boot.ini", "win.ini", "autoexec.bat", 
	"config.sys", "io.sys", "msdos.sys", "pagefile.sys", 
	"inetd.conf", "host.conf");
foreach d (dangerous_file)
{
  r = gnutella_search(socket: soc, search: d);
  if (! isnull(r) && ord(r[0]) > 0)
  {
    close(soc);
    security_hole(port);
    exit(0);
  }
}

close(soc);
