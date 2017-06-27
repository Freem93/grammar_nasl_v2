#
# (C) Tenable Network Security, Inc.
# 

# @PREFERENCES@


include("compat.inc");

if(description)
{
 script_id(11865);
 script_version ("$Revision: 1.21 $");

 script_name(english:"SOCKS Server Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A SOCKS server is running on this host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a SOCKS (SOCKetS) server, which allows client
applications to operate transparently through a firewall." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/SOCKS" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/03");
 script_cvs_date("$Date: 2011/04/26 15:44:20 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Detect & inspect SOCKS4/5 servers");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports("Services/socks", 1080, 9050, 7777);
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 #script_add_preference(name: "Quick SOCKS proxy checking", type:"checkbox", value:"no");
 exit(0);
}

########
include("global_settings.inc");
include("misc_func.inc");

function mark_socks_proxy(port, ver, ext_ip, authm)
{
  local_var	rep;

  #display("ver=", ver, "\text_ip=", ext_ip, "\tauth=", authm, "\n");
  register_service(port: port, proto: "socks"+ver);
  rep = strcat('\nA SOCKS', ver, ' server is running on this port\n');
  if (ext_ip)
  {
    rep = strcat(rep, 'Its external interface address is ', ext_ip, '\n');
    set_kb_item(name:"socks"+ver+"/external_addr/"+port, value: ext_ip);
  }
  else
    rep = strcat(rep, 'We could not determine its external interface address\n');
  if (! isnull(authm))
  {
    set_kb_item(name: "socks"+ver+"/auth/"+port, value: authm);
    if (authm == 0)
      rep = strcat(rep, 'It does not require authentication, or does not implement it.\n');
    else if (authm == 1)
      rep = strcat(rep, 'It prefers the username/password authentication.\n');
    else if (authm == 2)
      rep = strcat(rep, 'It prefers the GSS API authentication.\n');
    else if (authm == 255)
      rep = strcat(rep, 'It rejected all standard authentication methods (none, password, GSS API).\n');
    else
      rep = strcat(rep, 'It prefers the unknown ', authm, ' authentication method (bug?)\n');
  }
  security_note(port: port, extra: rep);
}

function test_socks(port)
{
  local_var	soc, req4, data, ext, exp, req5, authm;

  soc = open_sock_tcp(port);
  if(! soc) return;

#
# SOCKS4 request: 
# 1	Version number (4)
# 1	Command (1: connect / 2: bind)
# 2	Port
# 4	Address
# Var	UserID
# 1	zero (0)
#
# Bind: (local) port = 65535; expected remote address = 10.10.10.10
  req4 = raw_string(4, 2, 255, 255, 10, 10, 10, 10);
  req4 += "root";
  req4 += raw_string(0);
  send(socket: soc, data: req4);
  data = recv(socket: soc, length: 8);
  if (strlen(data) == 8)
  {
# SOCKS4 answer:
# 1	version (0)
# 1	code (90 -> 92)
# 2	port (or 0)
# 4	IP (or 0)
    if (ord(data[0]) == 0 && ord(data[1]) >= 90 && ord(data[1]) <= 93)
    {
      # Looks like a SOCKS4 server
      if (ord(data[1]) == 90)
      {
        ext = strcat(ord(data[4]), '.', ord(data[5]), '.', ord(data[6]), '.', ord(data[7]));
      }
      else
        exp = NULL;
      mark_socks_proxy(port: port, ver: 4, ext_ip: ext);
    }
  }
  close(soc);
######
#  SOCKS5 connection: 
#  1	Version number (5)
#  1	# of auth methods 
#  Var	Array of methods:
#	1	Method number:	0: no auth
#				1: GSSAPI
#				2: password 
#				3-7F: IANA reserved,
#				80-FE: user reserved
#				FF: no method 
# We should announce at least GSS API to be RFC conformant.
#
# The server answers:
# 1	Version
# 1	Chosen method (or FF if failure)
#
  soc = open_sock_tcp(port);
  if (!soc) return;
  req5 = raw_string(5, 3, 0, 1, 2);
  send(socket: soc, data: req5);
  data = recv(socket: soc, length: 2);
  if (strlen(data) == 2)
  {
    if (ord(data[0]) == 5 && (ord(data[1]) <= 2 || ord(data[1]) == 255))
    {
      authm = ord(data[1]);
      # Really looks like a SOCKS5 server
      req5 = raw_string(5, 2, 0, 1, 10, 10, 10, 10, 255, 255);	# BIND
      send(socket: soc, data: req5);
      data = recv(socket: soc, length: 10);
      if (strlen(data) < 2 || ord(data[1]) != 0 || ord(data[3]) != 1)
        ext = NULL;
      else
        ext = strcat(ord(data[4]), '.', ord(data[5]), '.', ord(data[6]), '.', ord(data[7]));
      mark_socks_proxy(port: port, ver: 5, ext_ip: ext, authm: authm);
    }
  }
}

quick_check = 0;
#q = script_get_preference("Quick SOCKS proxy checking");
#quick_check =  (q == "yes");

s = get_kb_list("Services/socks4");
if(!isnull(s))s = make_list(s);
else s = make_list();

s2 =  get_kb_list("Services/socks5");
if(!isnull(s2))s2 = make_list(s2);
else s2 = make_list();

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
 s3 = get_kb_list("Services/unknown");
 if(!isnull(s3)) s3 = make_list(s3);
 else s3 = make_list();
}
 else s3 = make_list();

ports = make_list(1080, 9050, 7777, s, s2);
if (! quick_check)
  ports = make_list(ports,s3);

prev_port = 0;
ports = sort(ports);

foreach port (ports)
  if(port != prev_port)
  {
    prev_port = port;
    if (get_port_state(port) && service_is_unknown(port: port) && port != 135 && port != 139 && port != 445 )
      test_socks(port: port);
  }


