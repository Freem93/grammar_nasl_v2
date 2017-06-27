#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11153);
 script_version("$Revision: 1.315 $");
 script_cvs_date("$Date: 2016/05/26 16:04:30 $");

 script_name(english:"Service Detection (HELP Request)");
 script_summary(english:"Sends 'HELP' to unknown services and looks at the answer.");

 script_set_attribute(attribute:"synopsis", value:
"The remote service could be identified.");
 script_set_attribute(attribute:"description", value:
"It was possible to identify the remote service by its banner or by
looking at the error message it sends when it receives a 'HELP'
request.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english: "Service detection");

 script_dependencie("find_service1.nasl", "find_service_3digits.nasl", "rpcinfo.nasl", "dcetest.nasl", "apache_SSL_complain.nasl");
# Do *not* add a port dependency  on "Services/unknown"
# Some scripts must run after this script even if there are no
# unknown services
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if ( get_kb_item("global_settings/disable_service_discovery") )
 exit(0, "Service discovery is disabled.");

#------------------------------------#
# Async socket support (Nessus 3.2)  #
#------------------------------------#
S_STATE_CONNECTING = 1;
S_STATE_READING    = 2;
S_STATE_DONE       = 3;

g_timestamps = make_list();
g_sock_state = make_list();
g_sock = make_list();
g_banners = make_list();
g_port_pool = make_list();
g_port_pool_max = 0;
g_port_pool_idx = 0;

CONNECT_TIMEOUT = 4;
TIMEOUT = 4;
MAX_SIMULT_CONNECTIONS = 10;

function port_push()
{
 if ( isnull(_FCT_ANON_ARGS[0]) ) return;
 g_port_pool[g_port_pool_max++] = _FCT_ANON_ARGS[0];
}

function port_pop()
{
 if ( g_port_pool_idx  >= g_port_pool_max ) return NULL;
 return g_port_pool[g_port_pool_idx++];
}

function port_new()
{
 local_var port;
 
 port = port_pop();
 if ( port == NULL ) return FALSE;
 g_sock_state[port] = S_STATE_CONNECTING;
 g_timestamps[port] = unixtime();
 
 g_sock[port] = open_sock_tcp(port, nonblocking:TRUE);
 return TRUE;
}

function port_done()
{
 local_var port;

 port = _FCT_ANON_ARGS[0];
 g_sock_state[port] = S_STATE_DONE;
 close(g_sock[port]);
 g_sock[port] = NULL;
 port_new();
}

function select()
{
 local_var port;
 local_var now;
 local_var e;
 local_var num;

 num = 0;
 now = unixtime();
 foreach port ( keys(g_sock) )
 {
  if ( g_sock_state[port] == S_STATE_CONNECTING )
  {
   num ++;
   e = socket_get_error(g_sock[port]);
   if ( e != 0 && e != EINPROGRESS )  port_done(port);
   else
   {
    e = socket_ready(g_sock[port]);
    if ( e > 0 ) 
	{	
	 send(socket:g_sock[port], data:'HELP\r\n');
 	 g_sock_state[port] = S_STATE_READING;
	 g_timestamps[port] = unixtime();
	}
   else if ((e == 0 &&  socket_get_error(g_sock[port]) != 0 && socket_get_error(g_sock[port]) != EINPROGRESS) ||
	    (e < 0) ||
	    ( now - g_timestamps[port]  >= CONNECT_TIMEOUT ) )
			port_done(port);
   }
  }
 else if ( g_sock_state[port] == S_STATE_READING )
  {
   num ++;
   if ( socket_pending(g_sock[port]) )
	{
	  g_banners[port] = recv(socket:g_sock[port], length:65535);
	  port_done(port);
	}
   else if ( now - g_timestamps[port] >= TIMEOUT ) port_done(port);
  }
 }
 return num;
}

#-------------------------------------------------------------------------#

function report_and_return(port, data, hole)
{
  if (data)
  {
    local_var c;
    c = data[strlen(data)-1];
    if (c != '.' && c != '\r' && c != '\n') data += '.';
  }

  if (hole)
  {
    if ( NASL_LEVEL < 3000 ) security_hole(port: port, data: data);
    else security_hole(port: port, extra: data);
  }
  else
  {
    if ( NASL_LEVEL < 3000 ) security_note(port: port, data: data);
    else security_note(port: port, extra: data);
  }

  return 1;
}

#--------------------------------------------------------------------------------------------------------------#

function identify(r, rget, port)
{
 local_var rep, a, v, banner, k, r_len, report, linesH, sub;
 r_len = strlen(r);

 linesH = split(r);
# Looks like it did not answer to "GET / HTTP/1.0". Strange...
# Submitted by Chuck Hein <chein2@geekdude.com>
# Port : 1344 - Type : help
# 0x00: 49 43 41 50 2F 31 2E 30 20 34 30 30 20 4F 4B 0D ICAP/1.0 400 OK.
# 0x10: 0A 44 61 74 65 3A 20 54 68 75 2C 20 33 31 20 4A .Date: Thu, 31 J
# 0x20: 75 6C 20 32 30 30 38 20 30 36 3A 33 39 3A 33 31 ul 2008 06:39:31
# 0x30: 20 47 4D 54 0D 0A 53 65 72 76 65 72 3A 20 52 65 GMT..Server: Re
# 0x40: 63 6F 6E 6E 65 78 20 49 43 41 50 20 53 65 72 76 connex ICAP Serv
# 0x50: 65 72 2F 31 2E 30 0D 0A 43 6F 6E 6E 65 63 74 69 er/1.0..Connecti
# 0x60: 6F 6E 3A 20 63 6C 6F 73 65 0D 0A 49 53 54 61 67 on: close..ISTag
# 0x70: 3A 20 22 52 65 63 6F 6E 6E 65 78 2D 30 33 32 33 : "Reconnex-0323
# 0x80: 30 36 2D 32 30 30 38 2D 61 31 33 32 66 32 22 0D 06-2008-a132f2".
# 0x90: 0A 45 6E 63 61 70 73 75 6C 61 74 65 64 3A 20 6E .Encapsulated: n
# 0xA0: 75 6C 6C 2D 62 6F 64 79 3D 30 0D 0A 0D 0A ull-body=0....

 if (ereg(string: chomp(linesH[0]), pattern: "^ICAP/1\.0 +[1-5]0[0-9]"))
 {
   register_service(port:port, proto:"icap");	# See RFC 3507
   report_and_return(port:port, data: "An ICAP server is running on this port.");
   return 1;
 }

 if (
   (rget == 'ERROR\r\n' && r == 'ERROR\r\nERROR\r\n' ) ||
   (r == 'ERROR\r\n' && rget == 'ERROR\r\nERROR\r\n' )
 )
 {
 	set_kb_item(name:"memcached/possible_port", value:port);
	# continue the code
 }

 else if (rget == 'ERROR\r\n')
 {
   register_service(port:port, proto:"mxdomainmgr");
   report_and_return(port:port, data:"The remote host is running a mxdomainmgr service on this port.");
 }

# The full banner is (without end of line:
# ( success ( 1 2 ( ANONYMOUS ) ( edit-pipeline ) ) )
if (( "success ( 1 2"  >< r ) || ("success ( 2 2"  >< r ))
{
 register_service(port:port, proto:"subversion");
 report_and_return(port:port, data:"A SubVersion server is running on this port.");
 return 1;
}

if ( r =~ "^@RSYNC" )
 {
 register_service(port:port, proto:"rsyncd");
 report_and_return(port:port, data:"An rsync server is running on this port.");
 return 1;
 }

if ( "Invalid protocol verification, illegal ORMI request" >< r )
{
 register_service(port:port, proto:"oracle_application_server");
 report_and_return(port:port, data:"An Oracle Application Server is running on this port.");
 return 1;
}

if ( raw_string(0x51, 0x00, 0x00, 0x00) >< r && port == 264 )
 {
 register_service(port:port, proto:"checkpoint_fw_ng_gettopo_port");
 report_and_return(port:port, data:"A Check Point FW NG gettopo_port service is running on this port.");
 return 1;
 }

# [root@f00dikator new_nasl_mods]# telnet 10.10.10.7 7110
# Trying 10.10.10.7...
# Connected to 10.10.10.7.
# Escape character is '^]'.
# hash 30026                              <------- Server
# yo there my brother from another mother <------- Client
# error NOT AUTHORIZED YET                <------- Server 

if ("error NOT AUTHORIZED YET" >< r)
{
 register_service(port:port, proto:"DMAIL_Admin");
 report_and_return(port:port, data:"The remote host is running a DMAIL Administrative service on this port.");
 return 1;
}

if ( "From Server : MESSAGE RECEIVED" >< r)
{
 register_service(port:port, proto:"shixxnote");
 report_and_return(port:port, data:"A shixxnote server is running on this port.");
 return 1;
}

# xmlns='jabber:client' xmlns:
# submitted by JYoung ~at- intramedplus.com 
if ( "xmlns='jabber:client'" >< r)
{
 register_service(port:port, proto:"ejabberd");
 report_and_return(port:port, data:"An ejabberd server is running on this port.");
 return 1;
}

#0x00: 3C 00 74 00 72 00 61 00 6E 00 73 00 6D 00 69 00 <.t.r.a.n.s.m.i.
#0x10: 73 00 73 00 69 00 6F 00 6E 00 20 00 74 00 79 00 s.s.i.o.n. .t.y.
#0x20: 70 00 65 00 3D 00 22 00 44 00 65 00 6E 00 69 00 p.e.=.".D.e.n.i.
#0x30: 65 00 64 00 22 00 3E 00 3C 00 68 00 65 00 61 00 e.d.".>.<.h.e.a.
#0x40: 64 00 65 00 72 00 20 00 65 00 6E 00 63 00 72 00 d.e.r. .e.n.c.r.
#0x50: 79 00 70 00 74 00 65 00 64 00 3D 00 22 00 46 00 y.p.t.e.d.=.".F.
#0x60: 61 00 6C 00 73 00 65 00 22 00 20 00 63 00 6F 00 a.l.s.e.". .c.o.
#0x70: 6D 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 m.p.r.e.s.s.e.d.
#0x80: 3D 00 22 00 46 00 61 00 6C 00 73 00 65 00 22 00 =.".F.a.l.s.e.".
#0x90: 20 00 2F 00 3E 00 3C 00 2F 00 74 00 72 00 61 00 ./.>.<./.t.r.a.
#0xA0: 6E 00 73 00 6D 00 69 00 73 00 73 00 69 00 6F 00 n.s.m.i.s.s.i.o.
if ('<\0t\0r\0a\0n\0s\0m\0i\0s\0s\0i\0o\0n\0 \0t\0y\0p\0e\0=\0"\0D\0e\0n\0i\0e\0d\0"\0' >< r &&
    '<\0/\0t\0r\0a\0n\0s\0m\0i\0s\0s\0i\0o\0n\0>' >< r  )
 {
 register_service(port:port, proto:"helm");
 report_and_return(port:port, data:"A HELM control panel server is running on this port.");
 return 1;
 }

# Submitted by Scott Bernal
# Port : 2160
# Type : help
# Banner : 
# 0x00: 73 65 72 76 65 72 3D 26 74 79 70 65 3D 30 26 69 server=&type=0&i
# 0x10: 64 3D 26 63 6F 75 6E 74 3D 31 26 6F 69 64 3D 2E d=&count=1&oid=.
# 0x20: 33 2E 34 2E 31 39 2E 32 2E 32 26 76 61 6C 75 65 3.4.19.2.2&value
# 0x30: 3D 26 65 72 72 6F 72 3D 34 0A 	       	     	=&error=4. 
if (r == 'server=&type=0&id=&count=1&oid=.3.4.19.2.2&value=&error=4\n')
{
register_service(port:port, proto:"apcpbeserver");
report_and_return(port:port, data:"APC PowerChute Business Edition Server is running on this port.");
 return 1;
}

if ( "Request with malformed data; connection closed" >< r )
{
 register_service(port:port, proto:"moodle-chat-daemom");
 report_and_return(port:port, data:"A Moodle Chat Daemon is running on this port.");
 return 1;
}

if ( "CONEXANT SYSTEMS, INC." >< r &&
     "ACCESS RUNNER ADSL TERMINAL" >< r )
{
 register_service(port:port, proto:"conexant_telnet");
 report_and_return(port:port, data:"A Conexant configuration interface is running on this port.");
 return 1;
}

if (r =~ '^0\\.[67]\\.[0-9] LOG\0 {16}')
{
 register_service(port: port, proto: "partimage");
 report_and_return(port:port, data:"Partimage is running on this port.
It requires a login.");
 return 1;
}

if (r =~ '^0\\.[67]\\.[0-9]\0 {16}')
{
 register_service(port: port, proto: "partimage");
 report_and_return(port:port, data:"Partimage is running on this port.
It does not require a login.");
 return 1;
}

if ("%x%s%p%nh%u%c%z%Z%t%i%e%g%f%a%C" >< r )
{
 register_service(port:port, proto:"egcd");
 report_and_return(port:port, data:"egcd is running on this port.");
 return 1;
}

if ( "f6ffff10" >< hexstr(r) && r_len < 6 )
{
 register_service(port:port, proto:"BackupExec");
 report_and_return(port:port, data:"A BackupExec Agent is running on this port.");
 return 1;
}

if (r == '\x00\x00\x00\x03')
{
 register_service(port:port, proto:"godm");
 report_and_return(port:port, data:"AIX Global ODM (a component from HACMP) is running on this port.");
 return 1;
}

if ('UNKNOWN COMMAND\n' >< r )
{
 register_service(port:port, proto:"clamd");
 report_and_return(port:port, data:"A clamd daemon, part of Clam AntiVirus, is running on this port.");
 return 1;
}

if ( "AdsGone 200" >< r && "HTML Ad" >< r )
{
 register_service(port:port, proto:"AdsGone");
 report_and_return(port:port, data:"An AdsGone proxy server is running on this port.");
 return 1;
}

if (egrep(pattern:"^Centra AudioServer", string:r) )
{
 register_service(port:port, proto:"centra");
 report_and_return(port:port, data:"A Centra audio server is running on this port.");
 return 1;
}

# TenFour TFS Secure Messaging Server, not RFC compliant
if ('Ok\r\n500 Command unknown' >< r )
{
 register_service(port:port, proto:"smtp");
 report_and_return(port:port, data:"An SMTP server is running on this port.");
 return 1;
}

if (
    "VERIFY = F$VERIFY" >< r || # Multinet 4.4 Imap daemon...
    "* OK dovecot ready." >< r ||
    "* OK Dovecot ready." >< r ||
    (
      stridx(r, '* OK ') == 0 &&
      (
        'CallPilot server ready' >< r ||
        'HELP BAD Error in IMAP command received by server.' >< r
      )
    ) ||
    # nb: hMailServer can be configured with a custom banner, in 
    #     which case this should still identify it.
    (
      stridx(r, '* OK ') == 0 &&
      '\r\nHELP BAD NULL COMMAND\r\n' >< r
    )
)
{
 register_service(port:port, proto:"imap");
 report_and_return(port:port, data:"An IMAP server is running on this port.");
 return 1;
}

if ("421 Server is temporarily unavailable - pleast try again later" >< r &&
    "421 Service closing control connection" >< r)
{
 register_service(port:port, proto:"ftp-disabled");
 report_and_return(port:port, data:"A (disabled) FTP server is running on this port.");
 return 1;
}

if ("RSTP/1.0 505 RSTP Version not supported" >< r )
{
 register_service(port:port, proto:"rtsp");
 report_and_return(port:port, data:"A RSTP (shoutcast) server is running on this port.");
 return 1;
}

if ("ERR INVALID-ARGUMENT" >< r &&
    "ERR UNKNOWN-COMMAND" >< r )
{
 register_service(port:port, proto:"nut");
 report_and_return(port:port, data:"A Network UPS Tool (NUT) server is running on this port.");
 return 1;
}

if ('\x80\x3d\x01\x03\x01' >< r)
{
 # http://osiris.shmoo.com/
 register_service(port:port, proto:"osiris");
 report_and_return(port:port, data:"An Osiris daemon is running on this port.");
 return 1;
}

if ( 'CAP PH\r\n' >< r )
{
 register_service(port:port, proto:"BrightMail_AntiSpam");
 report_and_return(port:port, data:"BrightMail AntiSpam is running on this port.");
 return 1;
}
if ('\xea\xdd\xbe\xef' >< r)
{
 register_service(port:port, proto:"veritas-netbackup-client");
 report_and_return(port:port, data:"Veritas NetBackup Client Service is running on this port.");
 return 1;
}

# http://www.cisco.com/en/US/products/sw/voicesw/ps556/products_tech_note09186a00801a62b9.shtml#topic1
if ('\x70\x5f\x0a\x10\x01' >< r)
{
 register_service(port:port, proto:"cisco-ris-data-collector");
 report_and_return(port:port, data:"A CISCO RIS Data Collector is running on this port.");
 return 1;
}

if ("Hello, this is quagga" >< r || "Hello, this is Quagga" >< r)
{
 register_service(port:port, proto:"quagga");
 report_and_return(port:port, data:"A BGP daemon from Quagga is listening on this port.");
 return 1;
}

if ( 'Hello\n' >< r )
{
 register_service(port:port, proto:"musicdaemon");
 report_and_return(port:port, data:"musicdaemon is listening on this port.");
 return 1;
}

if (egrep(pattern:"^220.*Administrator Service ready\.", string:r) ||
    egrep(pattern:"^220.*eSafe@.*Service ready", string:r))
{
 register_service(port:port, proto:"smtp");
 return 1;
}

if ( "Integrated port" >< r && "Printer Type" >< r && "Print Job Status" >< r)
{
  # This is a "fake" finger server, showing the printer status.
  # see bug#496
 register_service(port:port, proto:"finger-lexmark");
 return 1;
}

if ("Invalid password!!!" >< r || 
    "Incorrect password!!!" >< r )
{
 register_service(port:port, proto:"wollf");
 report_and_return(port:port, data:"A Wollf backdoor is running on this port.");
 return 1;
}

if ("version report" >< r )
{
# MA 2006-08-15: other tests report this as "pioneers-meta-server"
 register_service(port:port, proto:"gnocatan");
 report_and_return(port:port, data:"A Pioneers / Gnocatan game server is running on this port.");
 return 1;
}

if ("Welcome on mldonkey command-line" >< r)
{
 register_service(port:port, proto:"mldonkey-telnet");
 report_and_return(port:port, data:"A MLdonkey telnet interface is running on this port.");
 return 1;
}

if ( egrep(pattern:"^connected\. .*, version:", string:r) ||
     r == "PWD" )
{
 register_service(port:port, proto:"subseven");
 report_and_return(port:port, data:"A subseven backdoor is running on this port.");
 return 1;
}

if ( egrep(pattern:"^220 Bot Server", string:r) ||
     '\xb0\x3e\xc3\x77\x4d\x5a\x90' >< r )
{
 register_service(port:port, proto:"agobot.fo");
 report_and_return(port:port, data:"An Agobot.fo backdoor is running on this port.");
 return 1;
}

if ( "RemoteNC Control Password:" >< r )
{
 register_service(port:port, proto:"RemoteNC");
 report_and_return(port:port, data:"A RemoteNC console is running on this port.");
 return 1;
}

if ( "Sensor Console Password:" >< r )
{
 register_service(port:port, proto:"fluxay");
 report_and_return(port:port, data:"A fluxay sensor is running on this port.");
 return 1;
}

if ('\x3c\x65\x72\x72\x6f\x72\x3e\x0a' >< r)
{
 register_service(port:port, proto:"gkrellmd");
 report_and_return(port:port, data:"A gkrellmd system monitor daemon is running on this port.");
 return 1;
}
 
# QMTP / QMQP
if (r =~ '^[1-9][0-9]*:[KZD]')
{
  register_service(port: port, proto: "QMTP");
  report_and_return(port: port, data: "A QMTP / QMQP server is running on this port.");
}

# BZFlag Server (a game on SGI)
if (r =~ '^BZFS')
{
 register_service(port:port, proto:"bzfs");
 report_and_return(port:port, data:"A BZFlag game server seems to be running on this port.");
 return 1;
}

# SGUIL (Snort Monitoring Console)
if ( ("SGUIL" >< r) && ereg(pattern:"^SGUIL-[0-9]+\.[0-9]+\.[0-9]+ OPENSSL (ENABLED|DISABLED)", string:r))
{
 register_service(port:port, proto:"sguil");
 report_and_return(port:port, data:"A SGUIL server (Snort Monitoring Console) seems to be running on this port.");
 return 1; 
}

if ( '!Error\nSession not verified.\n' >< r )
{
 register_service(port:port, proto:"brocade-session");
 report_and_return(port:port, data:"A Brocade service seems to be running on this port.");
 return 1;
}

# (Solaris) lpd server
if(ereg(pattern: "^Invalid protocol request.*:HHELP.*", string:r))
{
 register_service(port:port, proto:"lpd");
 report_and_return(port:port, data:"An LPD server seems to be running on this port.");
 return 1;
}

if (r_len == 4 && '\x3d\x15\x1a\x3d' >< r)
{
 register_service(port:port, proto:"hacker_defender");
 report_and_return(port:port, data:"An 'Hacker Defender' backdoor seems to be running on this port.");
 return 1;
}

# http://hea-www.harvard.edu/RD/ds9/
if ("XPA$ERROR unknown xpans request:" >< r )
{
 register_service(port:port, proto:"DS9");
 report_and_return(port:port, data:'A DS9 service seems to be running on this port.\nSee also : http://hea-www.harvard.edu/RD/ds9/');
 return 1;
}

if ('421 Unauthorized connection to server\n' >< r )
{
 register_service(port:port, proto:"ncic");
 report_and_return(port:port, data:"A NCIC service seems to be running on this port.");
 return 1;
}

if ( r_len == 4 && '\x09\x50\x09\x50' ><  r)
{
 register_service(port:port, proto:"dell_management_client");
 report_and_return(port:port, data:"A Dell Management client seems to be running on this port.");
 return 1;
}

if ( "gdm already running. Aborting!" >< r )
{
 register_service(port:port, proto:"xdmcp");
 report_and_return(port:port, data:"An xdmcp server seems to be running on this port.");
 return 1;
}

if ( r_len == strlen("20040616105304") &&
      ereg(pattern:"200[0-9][01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]$",
	   string:r))
 {
 register_service(port:port, proto:"LPTOne");
 report_and_return(port:port, data:"A LPTOne server seems to be running on this port.");
 return 1;
}

if ('ERROR Not authenticated\n' >< r )
{
 register_service(port:port, proto:"hpjfpmd");
 report_and_return(port:port, data:"An HP WebJetAdmin server seems to be running on this port.");
 return 1;
}

if ( "500 P-Error" >< r && "220 Hello" >< r )
{
 register_service(port:port, proto:"unknown_irc_bot");
 report_and_return(port:port, data:"An IRC bot seems to be running on this port.");
 return 1;
}

if ( "220 WinSock" >< r )
{
 register_service(port:port, proto:"winsock");
 report_and_return(port:port, data:"A WinSock server seems to be running on this port.");
 return 1;
}

if ( "DeltaUPS:" >< r )
{
 register_service(port:port, proto:"delta-ups");
 report_and_return(port:port, data:"A DeltaUPS monitoring server seems to be running on this port.");
 return 1;
}

if ( ereg(pattern:"lpd: .*", string:r) || 'An lpd test connection was' >< r )
{
 register_service(port:port, proto:"lpd");
 report_and_return(port:port, data:"An LPD server seems to be running on this port.");
 return 1;
}

if(ereg(pattern: "^/usr/sbin/lpd.*", string:r))
{
 register_service(port:port, proto:"lpd");
 report_and_return(port:port, data:"An LPD server seems to be running on this port.");
 return 1;
}

# See <http://sourceware.org/cluster/conga/> for more info.
if (
  '<?xml version="1.0"?>\n<Clients_SSL_certificate_required/>\n' == r ||
  '<?xml version="1.0"?>\n<SSL_required/>\n' == r
)
{
 register_service(port:port, proto:"ricci");
 report_and_return(
  port:port, 
  data:string(
   "A ricci agent seems to be listening on this port. Ricci is the agent\n",
   "component of Conga and is used for cluster and storage configuration /\n",
   "monitoring."
  )
 );
 return 1;
}

if ( strlen(r) > 32 ) sub = substr(r, 0, 31);
else sub = r;

if ( "<!doctype html" >< tolower(r) ||
     r =~ "^<HEAD><TITLE>" ||	
     "<html>" >< tolower(sub) )
{
 register_service(port:port, proto:"www");
 report_and_return(port:port, data:"A web server seems to be running on this port.");
 return 1;
}
if("An lpd test connection was completed" >< r || 
    "Bad from address." >< r || 
    "your host does not have line printer access" >< r ||
    "does not have access to remote printer" >< r )
{
 register_service(port:port, proto:"lpd");
 report_and_return(port:port, data:"An LPD server seems to be running on this port.");
 return 1;
}

# PPR
if (r =~ "^lprsrv: unrecognized command:")
{
  register_service(port:port, proto:"lpd");
  report_and_return(port:port, data:"PPR seems to be running on this port.");
  return 1;
}

if(ereg(pattern:"^login: Password: (Login incorrect\.)?$", string:r) ||
   ereg(pattern:"^login: Login incorrect\.", string:r))
{
 register_service(port:port, proto:"uucp");
 report_and_return(port:port, data:"A UUCP daemon seems to be running on this port.");
 return 1;
}
if(ereg(pattern:"^login: Login incorrect\.$", string:r))
{
 register_service(port:port, proto:"uucp");
 report_and_return(port:port, data:"A UUCP daemon seems to be running on this port.");
 return 1;
}

# IRC server
if (ereg(pattern: "^:.* 451 .*:", string:r))
{
  register_service(port: port, proto: "irc");
  report_and_return(port: port, data: "An IRC server seems to be running on this port.");
  return 1;
}

if(ereg(pattern:'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[e\xE9]c|F[e\xE9]v|Avr|Mai|Ao[u\xFB]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$',
        string:r) ||
   ereg(pattern:'^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[e\xE9]c|F[e\xE9]v|Avr|Mai|Ao[u\xFB]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$', string:r, icase: 1) ||
   r =~ '^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$' ||
   r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$' ||
   ereg(pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r) ||
# MS flavor of daytime
   ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r) ||
   r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0?[1-9]|[12][0-9]|3[01])/(0?[1-9]|1[0-2]|3[01])/(19|20)[0-9][0-9][ \t\r\n]*$' )
{
  register_service(port:port, proto:"daytime");
  report_and_return(port: port, data: "Daytime is running on this port.");
  return 1;
}

# Banner:
# HP OpenView OmniBack II A.03.10:INET, internal build 325, built on Mon Aug 23 15:50:58 1999. 
if (match(string: r, pattern: "HP OpenView OmniBack II*"))
{
  register_service(port: port, proto: "omniback");
  report_and_return(port: port, data: "HP Omniback seems to be running on this port.");
  return 1;
}

# Banner:
# HP OpenView Storage Data Protector A.05.00: INET, internal build 190, built on Tue Jul 16 17:37:32 2002.
if (match(string: r, pattern: "HP OpenView Storage Data Protector"))
{
  register_service(port: port, proto: "hpov-storage");
  report_and_return(port: port, data: "HP OpenView Storage Data Protector seems to be running on this port.");
  return 1;
}

# Veritas Netbackup
if (r =~ '^1000 +2\n43\nunexpected message received' ||
    "gethostbyaddr: No such file or directory" >< r )
{
  register_service(port: port, proto: "netbackup");
  report_and_return(port: port, data: "Veritas Netbackup seems to be running on this port.");
  return 1;
}

# BMC Patrol
if (r == "SDPACK")
{
  register_service(port: port, proto: "bmc-perf-sd");
  report_and_return(port: port, data: "BMC Perform Service Daemon seems to be running on this port.");
  return 1;
}

# SNPP
if (r =~ '^220 .* SNPP ' || egrep(string: r, pattern: '^214 .*PAGE'))
{
  register_service(port: port, proto: "snpp");
  report_and_return(port: port, data: "A SNPP server seems to be running on this port.");
  return 1;
}

# HylaFax FTP
if (egrep(string: r, pattern: '^214-? ') && 'MDMFMT' >< r)
{
  register_service(port: port, proto: "hylafax-ftp");
  report_and_return(port: port, data: "A HylaFax server seems to be running on this port.");
  return 1;
}

# HylaFAX  (hylafax spp?)
if ( egrep(string:r, pattern:"^220.*HylaFAX .*Version.*") )
{
  register_service(port: port, proto: "hylafax");
  report_and_return(port: port, data: "A HylaFax server seems to be running on this port.");
  return 1;
}

if ( egrep (string:r, pattern:"^S: FTGate [0-9]+\.[0-9]+") )
{
  register_service(port: port, proto: "ftgate-monitor");
  report_and_return(port: port, data: "A FTGate Monitor server seems to be running on this port.");
  return 1;
} 

# IRCn
if (r_len == 2048 && r =~ '^[ ,;:.@$#%+HMX\n-]+$' && '-;;=' >< r &&
	'.;M####+' >< r && '.+ .%########' >< r && ':%.%#########@' >< r)
{
  register_service(port: port, proto: 'IRCn-finger');
  report_and_return(port: port, data: "IRCn finger service seems to be running on this port.");
  return 1;
}

if ("Melange Chat Server" >< r)
{
  register_service(port: port, proto: 'melange-chat');
  report_and_return(port: port, data: "Melange Chat Server is running on this port.");
  return 1;
}

# http://www.directupdate.net/
if (r =~ '^OK Welcome .*DirectUpdate server')
{
  register_service(port: port, proto: 'directupdate');
  report_and_return(port: port, data: "A DirectUpdate server is running on this port.");
  return 1;
}

# http://www.xboxmediaplayer.de
if (r == "HELLO XBOX!")
{
  register_service(port: port, proto: 'xns');
  report_and_return(port: port, data: "A XNS streaming server seems to be running on this port.");
  return 1;
}

# Windows 2000 BackupExec
if (r == '\xf6\xff\xff\xff\x10')
{
  register_service(port: port, proto: "backupexec");
  report_and_return(port: port, data: "A BackupExec server seems to be running on this port.");
  return 1;
}

# SAP/DB niserver (default port = 7269)
# 0000 4c 00 00 00 03 ff 00 00 ff ff ff ff ff ff ff ff
# 0020 01 00 04 00 4c 00 00 00 00 02 34 00 ff 0d 00 00
# 0040 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
# 0060 00 00 00 00 2e 0f 13 40 00 00 00 00 89 74 09 08
# 0100 05 49 2d 31 00 04 50 ff ff 03 52 01

if (substr(r, 0, 15) == hex2raw(s: "4c00000003ff0000ffffffffffffffff"))
{
  register_service(port: port, proto: "sap_db_niserver");
  report_and_return(port: port, data: "SAP/DB niserver seems to be running on this port.");
  return 1;
}

# Submitted by Lyal Collins
# 00: 01 09 d0 02 ff ff 01 03 12 4c .. . ...L
# DB2 V6 and possibly Db2 V7, running on zOS - TCP ports 446 and 448
if (r == '\x01\x09\xD0\x02\xFF\xFF\x01\x03\x12\x4C')
{
  register_service(port: port, proto: "db2");
  report_and_return(port: port, data: "DB2 is running on this port.");
  return 1;
}

# Check Point FW-1 Client Authentication (TCP/259)
# 00: 43 68 65 63 6b 20 50 6f 69 6e 74 20 46 69 72 65 Check Point Fire
# 10: 57 61 6c 6c 2d 31 20 43 6c 69 65 6e 74 20 41 75 Wall-1 Client Au
# 20: 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 53 65 72 thentication Ser
# 30: 76 65 72 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 67 ver running on g
# 40: 61 74 65 6b 65 65 70 65 72 30 31 2e 6b 61 69 73 atekeeper01.kais
# 50: 65 72 6b 72 61 66 74 2e 64 65 0d 0a 0d ff fb 01 erkraft.de... .
# 60: ff fe 01 ff fb 03 55 73 65 72 3a 20 47 45 54 20 . .User: GET
# 70: 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 / HTTP/1.0..User
# 80: 20 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 30 20 GET / HTTP/1.0
# 90: 6e 6f 74 20 66 6f 75 6e 64 0d 0a 0d 0d 0a 55 73 not found.....Us
# a0: 65 72 3a 20 er: 

if ("Check Point FireWall-1 Client Authentication Server" >< r)
{
  register_service(port: port, proto: "fw1_client_auth");
  report_and_return(port: port, data: "Check Point FireWall-1 Client Authentication Server seems to be running on this port.");
  return 1;
}

# Seen on FW1-topo and other ports
if (r == 'Y\0\0\0')
{
  register_service(port: port, proto: "fw1_generic");
  report_and_return(port: port, data: "A Check Point FireWall-1 service seems to be running on this port.");
  return 1;
}

if (r =~ "^200 .* (PWD Server|poppassd)")
{
  register_service(port: port, proto: "pop3pw");
  report_and_return(port: port, data: "A poppassd server seems to be running on this port.");
  return 1;
}

# Ebola antivirus
if ("Welcome to Ebola " >< r )
{
 register_service( port : port, proto: "ebola" );
 set_kb_item(name:"ebola/banner/" + port, value: r );
 report_and_return(port : port, data: "An Ebola server is running on this port :\n" + r );
 return 1;
}

# www.midas.org
if (r =~ '^MIDASd v[2-9.]+[a-z]? connection accepted')
{
  register_service(port: port, proto: 'midas');
  report_and_return(port: port, data: "A MIDAS server is running on this port.");
  return 1;
}

# Crystal Reports
# 00: 73 65 72 76 65 72 20 31 32 38 2e 31 32 38 2e 32 server 128.128.2
# 10: 2e 31 39 37 20 33 2e 35 33 2e 31 61 20 63 6f 6e .197 3.53.1a con
# 20: 6e 65 63 74 69 6f 6e 73 3a 20 32 0a nections: 2. 
# MA 2007-03-04
# I got *exactly* the same reply from 4JS on port 6400.

if (r =~ '^server [0-9.]+ connections: [0-9]+' ||
    r =~ '^server [0-9.]+ [0-9a-z.]+ connections: [0-9]+')
{
  register_service(port: port, proto: 'crystal');
  report_and_return(port: port, data: 'Crystal Reports or 4JS seems to be running on this port.');
  return 1;
}

# Trueweather taskbar applet
if (r =~ '^TrueWeather\r\n\r\n')
{
  register_service(port: port, proto: 'trueweather');
  report_and_return(port: port, data: 'TrueWeather taskbar applet is running on this port.');
  return 1;
}

# W32.IRCBot.E or W32.IRCBot.F or W32.Randex or W32.Korgo.V
if (r == '220 \r\n331 \r\n230 \r\n')
{
  register_service(port: port, proto: 'ircbot');
  report_and_return(port: port, data: 'A W32.IRCBot backdoor is running on this port.');
  return 1;
}

if (ereg(string: r, pattern: "^RTSP/1\.0 "))
{
  if (
    "403 Proxy denied" >< r ||
    "500 Unknown proxy error" >< r ||
    "503 Too many proxy users" >< r
  )
  {
    register_service(port:port, proto:'rtsp_proxy');
    report_and_return(port:port, data:"A streaming proxy server is running on this port.");
  }
  else
  {
    register_service(port:port, proto:'rtsp');
    report_and_return(port:port, data:"A streaming server is running on this port.");
  }
  return 1;
}

# BMC's ECS product (part of Control-M) gateway listener
# 00: 61 20 30 30 30 30 30 30 32 64 47 52 30 39 33 32    a 0000002dGR0932
# 10: 30 30 30 30 39 30 43 47 47 41 54 45 57 41 59 20    000090CGGATEWAY 
# 20: 30 43 47 55 31 30 30 33 31 30 30 36 30 43 47 5f    0CGU100310060CG_
# 30: 41 20 32 32 31 47 41                               A 221GA
if (r =~ '^a [0-9a-zA-Z]+GATEWAY [0-9A-Z]+_A [0-9A-Z]+')
{
  register_service(port: port, proto: 'ctrlm-ecs-gateway');
  report_and_return(port: port, data: "An ECS gateway listener (par of Control-M) is running on this port.");
  return 1;
}

# Running on 400/tcp?!
if (r == '\xDE\xAD\xF0\x0D')
{
  register_service(port: port, proto: 'jwalk');
  report_and_return(port: port, data: "A Seagull JWalk server is running on this port.");
  return 1;
}

# Contributed by Thomas Reinke - running on TCP/23
# Interface to ADSL router smc7204BRB 
if ("CONEXANT SYSTEMS, INC" >< r && "ACCESS RUNNER ADSL CONSOLE PORT" >< r 
    && "LOGON PASSWORD" >< r)
{
  register_service(port: port, proto: 'conexant-admin');
  report_and_return(port: port, data: "Interface of a Conexant ADSL router is running on this port.", hole:1);
  return 1;
}

# Default port = 9090
if (r == 'GET %2F HTTP%2F1.0\n')
{
  register_service(port: port, proto: 'slimserver');
  report_and_return(port: port, data: "The Slimserver streaming server (command interface) is running on this port.", hole:1);
  return 1;
}

# 00: 0d 0a 50 72 65 73 73 20 72 65 74 75 72 6e 3a 2a    ..Press return:*
# 10: 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a    ****************
# 20: 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f 72 64    ..Enter Password
# 30: 3a 2a 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f    :*..Enter Passwo
#  40: 72 64 3a
if ('Press return:*****************' >< r && 'Enter Password:' >< r)
{
  register_service(port: port, proto: 'darkshadow-trojan');
  report_and_return(port: port, data: "The Darshadow trojan horse seems to be running on this port.", hole:1);
  return 1;
}

# Contributed by David C. Shettler
# http://esupport.ca.com/index.html?/public/dto_transportit/infodocs/LI57895.asp
if (r == 'ACK')
{
  register_service(port: port, proto: 'tng-cam');
  report_and_return(port: port, data: 'CA Messaging (part of Unicenter TNG) is running on this port.', hole:1);
  return 1;
}

# Contributed by Jan Dreyer - unfortunately, I could not find much data on 
# this Trojan horse. It was found running on port 2400
# The banner is:
# +------------------------+
# | DllTrojan by ScriptGod |
# +------------------------+
# |       [27.04.04]       |
# +------------------------+
# enter pass:
#
if ("+------------------------+" >< r || "DllTrojan by ScriptGod" >< r)
{
  register_service(port: port, proto: 'dll-trojan');
  report_and_return(port: port, data: 'A trojan horse (DllTrojan) seems to be running on this port.\nClean your system.', hole:1);

  return 1;
}

# Submitted by Paul Weatherhead
if (r == '\x3d\x15\x1a\x3d')
{
  register_service(port: port, proto: 'rcserv-trojan');
  report_and_return(port: port, data: 'A trojan horse (RCServ) seems to be running on this port.\nYou should clean your system :\nthe executable file might be MDTC.EXE.', hole:1);
  return 1;
}

# $ telnet 10.10.1.203 5110
# Trying 10.10.1.203...
# Connected to 10.10.1.203.
# Escape character is '^]'.
# Sifre_Korumasi                                <------- Server
# HELP                                          <------- Client
# Sifre_Hatasi                                  <------- Server
# 000300Dedected burute force atack from your ip adress   <--- alternative response
#
# $ telnet 10.10.1.203 5112 (same for 51100)
# Trying 10.10.1.203...
# Connected to 10.10.1.203.
# Escape character is '^]'.
# 220 Welcom to ProRat Ftp Server               <------- Server
# HELP                                          <------- Client
# 500 'HELP': command not understood.           <------- Server
# 000300Dedected burute force atack from your ip adress   <--- alternative response
if (
  # nb: "Sifre Korumasi" means "password-protected" in Turkish
  #     and "Sifre Hatasi" means "invalid password".
  'Sifre_Korumasi' >< r || 
  '000300Dedected burute force atack from your ip adress' >< r ||
  ' Welcom to ProRat Ftp Server' >< r
) {
  register_service(port:port, proto:'prorat-trojan');
  report_and_return(
    port:port, 
    hole:1,
    data:string(
      "The Prorat trojan horse is running on the remote host. Block access\n",
      "to this port immediately and clean the system as soon as possible."
    )
  );
  return 1;
}

# False positives reported by Michel
#if (r == 'ERROR\n')
#{
#  register_service(port: port, proto: 'streaming21');
  #report_and_return(port: port, data: "A Streaming21 server seems to be running on this port");
# return 1;
#}

# Submitted by Adam Baldwin - Reference http://evilpacket.net
# Identifies Symantec ManHunt or SNS console (qsp proxy)
# 32 bytes of data sent when a connection is made
# 01 01 00 08 1C EE 01 00 00 00 00 00 00 00 00 00
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
if (r == '\x01\x01\x00\x08\x1c\xee\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
{
  register_service(port: port, proto: 'qsp-proxy');
  report_and_return(port: port, data: "A Symantec ManHunt / SNS console (QSP Proxy) seems to be running on this port.");
  return 1;
}

# sunRay Server - thanks to kent@unit.liu.se (Kent Engstrom)
if("ERR/InvalidCommand" >< r) 
{
 register_service(port:port, proto:"sunraySessionMgr");
 report_and_return(port:port, data:"sunraySessionMgr server is running on this port.");
 return 1;
}

# Sun Ray authentication daemon (contrib from Glenn M. Brunette, Jr.)
if (match(string: r, pattern: "protocolErrorInf error=Missing\*state=disconnected*"))
{
 register_service(port:port, proto:"sunray-utauthd");
 report_and_return(port:port, data:"sunray authentication daemon is running on this port.");
 return 1;
}
  
# Shoutcast
if (r =~ "^ICY 401")
{
  local_var verb;

  register_service(port: port, proto: "shoutcast");
  if ("icy-notice1:<BR>shoutcast " >< r) verb = "is";
  else verb = "seems to be";
  report_and_return(port: port, data: "A shoutcast server " + verb + " running on this port.");
  return 1;
}

# from Ryan Sweat
if ('invalid password\r\n' == r && (rget == r || strlen(rget) == 0))
{
  register_service(port: port, proto: "shoutcast_service");
  report_and_return(
    port:port, 
    data:string(
      "The remote service appears to be a SHOUTcast Server's service port, used\n",
      "to broadcast streams and administer the server."
    )
  );
  return 1;
}

# NFR
if (egrep(pattern:"^Getserver 1\.0 - identify yourself", string:r ) )
{
 register_service(port:port, proto:"nfr-admin-gui");
 report_and_return(port:port, data:"An NFR Administrative interface is listening on this port.");
 return 1;
}

# remstats.sf.net
if ( "ERROR: unknown directive: " >< r )
{
  register_service(port:port, proto:"remstats");
  report_and_return(port:port, data:"A remstats service is running on this port.");
  return 1;
}

if ( "NCD X Terminal Configuration" >< r )
{
  register_service(port:port, proto:"ncdx_term_config");
  report_and_return(port:port, data:"A NCD X Terminal Configuration service is running on this port.");
  return 1;
}

if ("NPC Telnet permit one" >< r )
{
  register_service(port:port, proto:"telnet");
  report_and_return(port:port, data:"A (NPC) telnet service is running on this port.");
  return 1;
}

if ( ( "Prisma Digital Transport" >< r && "Use the SNMP set community" >< r) ||
     ( "Wegener Communications Copyright" >< r && "Unit Label" >< r && "Type H for" >< r ) )
{
  register_service(port:port, proto:"telnet");
  report_and_return(port:port, data:"A telnet service is running on this port.");
  return 1;
}

if ( "SiteManager Proxy" >< r )
{
  register_service(port:port, proto:"site_manager_proxy");
  report_and_return(port:port, data:"A Site Manager Proxy service is running on this port.");
  return 1;
}

if ( egrep(pattern:"^GPSD,.*", string:r) )
{
  register_service(port:port, proto:"gpsd");
  report_and_return(port:port, data:"A gpsd daemon is running on this port.");
  return 1;
}

if ( egrep(pattern:"^200.*Citadel(/UX| server ready).*", string:r) )
{
  register_service(port:port, proto:"citadel/ux");
  report_and_return(port:port, data:"A Citadel/UX BBS is running on this port.");
  return 1;
}

if ( "Gnome Batalla" >< r )
{
 register_service(port:port, proto:"gnome_batalla");
 report_and_return(port:port, data:"A Gnome Batalla service is running on this port.");
  return 1;
}
   
if ("System Status" >< r && "Uptime" >< r )
{
  register_service(port:port, proto: "systat");
  report_and_return(port: port, data: "The systat service is running on this port.");
  return 1;
}

if ("ESTABLISHED" >< r && "TCP" >< r)
{
  register_service(port:port, proto: "netstat");
  report_and_return(port: port, data: "The netstat service is running on this port.");
  return 1;
}

if ( "charles dickens" >< tolower(r) || "george bernard shaw" >< tolower(r) || "a. a. milne" >< tolower(a) )
{
  register_service(port:port, proto: "qotd");
  report_and_return(port: port, data: "qotd (Quote of the Day) seems to be running on this port.");
  return 1;
}

if ("Can't locate loadable object for module" >< r && "BEGIN failed--compilation aborted" >< r )
{
  register_service(port:port, proto: "broken-perl-script");
  report_and_return(port: port, data: "A broken perl script is running on this port.");
  return 1;
}

if ("/usr/games/fortune: not found" >< r ||
    r =~ '^"[^"]+" *Autor desconocido[ \t\r\n]*$')
{
  register_service(port:port, proto: "qotd");
  report_and_return(port: port, data: "qotd (Quote of the Day) seems to be running on this port (misconfigured).");
  return 1;
}

if ("Check Point FireWall-1 authenticated Telnet server" >< r )
{
  register_service(port:port, proto: "fw1-telnet-auth");
  report_and_return(port: port, data: "A Firewall-1 authenticated telnet server is running on this port.");
  return 1;
}

# Added NOTICE * deviation to handle Charybdis
# :irctest.local NOTICE * :*** Looking up your hostname...
if ( "NOTICE AUTH : " >< r || "NOTICE * :***" >< r)
{
  register_service(port:port, proto: "irc");
  report_and_return(port: port, data: "An IRC server seems to be running on this port.");
  return 1;
}

# 00: 45 52 52 4f 52 3a 20 59 6f 75 72 20 68 6f 73 74 ERROR: Your host
# 10: 20 69 73 20 74 72 79 69 6e 67 20 74 6f 20 28 72 is trying to (r
# 20: 65 29 63 6f 6e 6e 65 63 74 20 74 6f 6f 20 66 61 e)connect too fa
# 30: 73 74 20 2d 2d 20 74 68 72 6f 74 74 6c 65 64 0d st -- throttled.
# 40: 0a .
# Suspicious test?

if (r == 'ERROR: Your host is trying to (re)connect too fast -- throttled\n')
{
  register_service(port:port, proto: "irc");
  report_and_return(port: port, data: "An IRC server might be running on this port.");
  return 1;
}

if (r =~ '^sh-[0-9.]+# ')
{
  register_service(port:port, proto: "wild_shell");
  report_and_return(port: port, data: "A shell seems to be running on this port! (this is a possible backdoor)", hole:1);
}

if ( ("Microsoft Windows" >< r) &&
     egrep(pattern:"\([c|C]\) (Copyright )?([0-9]+)", string:r) &&
     ("Microsoft Corp" >< r) ||
     # Answer to help
     "ASSOC" >< r && "ATTRIB" >< r && "BREAK" >< r && "CALL" >< r && 
     "CHDIR" >< r && "CHKDSK" >< r && "CLS" >< r && "COPY" >< r && 
     "DATE" >< r && "DEL" >< r )
{
  register_service(port:port, proto: "wild_shell");
  report_and_return(port: port, data: "A Windows shell seems to be running on this port! (this is a possible backdoor)", hole:1);
}

if ( "1|0|0||" >< r )
{
  register_service(port:port, proto: "PigeonServer");
  report_and_return(port: port, data: "PigeonServer seems to be running on this port.");
  return 1;
}

if (r =~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$')
{
 register_service(port:port, proto:"kde-lisa");
 report_and_return(port:port, data:"KDE Lisa server is running on this port.");
 return 1;
}

# Submitted by Lucian Ravac - See http://zabbix.org
if (
  stridx(r, 'ZBX_NOTSUPPORTED') == 0 ||
  (stridx(r, 'ZBXD') == 0 && stridx(r, 'ZBX_NOTSUPPORTED') == 13)
)
{
 register_service(port: port, proto: 'zabbix');
 report_and_return(port: port, data: 'A Zabbix agent is running on this port.');
 return 1;
}

# Submitted by Brian Spindel - Gopher on Windows NT
# 00: 33 20 2d 2d 36 20 42 61 64 20 52 65 71 75 65 73	3 --6 Bad Reques
# 10: 74 2e 20 0d 0a 2e 0d 0a 				t. 

if (r == '3 --6 Bad request. \r\n.\r\n') 
{
 register_service(port: port, proto: 'gopher');
 report_and_return(port: port, data: 'A Gopher server seems to be running on this port.');
 return 1;
}

# 00: 01 72 6c 6f 67 69 6e 64 3a 20 50 65 72 6d 69 73 .rlogind: Permis
# 10: 73 69 6f 6e 20 64 65 6e 69 65 64 2e 0d 0a sion denied... 

if (match(string: r, pattern: '\x01rlogind: Permission denied*', icase: 1))
{
 register_service(port: port, proto: 'rlogin');
 report_and_return(port: port, data: 'rlogind seems to be running on this port.');
 return 1;
}

# Submitted by Aaron Daugherty.
#
# 0x00:  01 72 6C 6F 67 69 6E 64 3A 20 4B 65 72 62 65 72    .rlogind: Kerber
# 0x10:  6F 73 20 41 75 74 68 65 6E 74 69 63 61 74 69 6F    os Authenticatio
# 0x20:  6E 20 6E 6F 74 20 65 6E 61 62 6C 65 64 2E 2E 0D    n not enabled...
# 0x30:  0A           
if (match(string: r, pattern: '\x01rlogind: Kerberos Authentication*', icase: 1))
{
 register_service(port: port, proto: 'rlogin');
 report_and_return(port: port, data: 'A Kerberized rlogind seems to be running on this port.');
 return 1;
}

# 00: 73 74 61 74 64 20 76 65 72 73 69 6f 6e 3a 33 2e statd version:3.
# 10: 32 20 6d 73 67 69 64 3a 32 30 30 35 2e 30 35 2e 2 msgid:2005.05.
# 20: 31 38 20 31 30 3a 35 30 3a 33 35 0d 0a 18 10:50:35..
# Note: this is *unreliable*, many clones exist
if (match(string: r, pattern: "statd version:*msgid:*"))
{
 register_service(port: port, proto: 'nagios-statd');
 report_and_return(port: port, data: 'nagios-statd seems to be running on this port.');
 return 1;
}

# Running on 632/tcp
# 00: 54 68 65 20 73 6d 62 72 69 64 67 65 20 69 73 20 The smbridge is
# 10: 75 73 65 64 20 62 79 20 31 37 32 2e 32 30 2e 34 used by 172.20.4
# 20: 35 2e 31 38 38 0a 0d 54 68 65 20 63 6c 69 65 6e 5.188..The clien
# 30: 74 20 69 73 20 63 6c 6f 73 65 64 21 0a 0d t is closed!..
if (match(string: r, pattern: 'The smbridge is used by*'))
{
 register_service(port: port, proto: 'smbridge');
 report_and_return(port: port, data: 'IBM OSA SMBridge seems to be running on this port.');
 return 1;
}

# Running on 8649
# 00: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31    <?xml version="1
# 10: 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 49 53    .0" encoding="IS
# 20: 4f 2d 38 38 35 39 2d 31 22 20 73 74 61 6e 64 61    O-8859-1" standa
# 30: 6c 6f 6e 65 3d 22 79 65 73 22 3f 3e 0a 3c 21 44    lone="yes"?>.<!D
# 40: 4f 43 54 59 50 45 20 47 41 4e 47 4c 49 41 5f 58    OCTYPE GANGLIA_X
# 50: 4d 4c 20 5b 0a 20 20 20 3c 21 45 4c 45 4d 45 4e    ML [.   <!ELEMEN
# 60: 54 20 47 41 4e 47 4c 49 41 5f 58 4d 4c 20 28 47    T GANGLIA_XML (G
# 70: 52 49 44 29 2a 3e 0a 20 20 20 20 20 20 3c 21 41    RID)*>.      <!A
if (match(string: r, pattern: '<?xml version=*') && " GANGLIA_XML " >< r &&
 "ATTLIST HOST GMOND_STARTED" >< r)
{
 register_service(port: port, proto: 'gmond');
 report_and_return(port: port, data: 'Ganglia monitoring daemon seems to be running on this port.');
 return 1;
}

# Cf. www.nmscommunications.com
if (match(string: r, pattern: 'Natural MicroSystem CTAccess Server *'))
{
 register_service(port: port, proto: 'ctaccess');
 report_and_return(port: port, data: 'Natural MicroSystem CTAccess Server is running on this port.');
 return 1;
}

# From Jason Johnson
if (r == '\x2f\x44\x94\x72')
{
 register_service(port: port, proto: 'spysweeper');
 report_and_return(port: port, data: 'Spy Sweeper Enterprise client seems to be running on this port.');
 return 1;
}

# From Justin Fanning
if (r =~ '^\r\nEfficient [0-9]+ DMT Roter .* Ready.*Login:')
{
 register_service(port: port, proto: 'efficient-router');
 report_and_return(port: port, data: 'An Efficient router administration interface is running on this port.'); 
 return 1;
}

# From Hartmut Steffin
# HG 1500 Router/Gate (GateKeeper?) built into a siemens HiPath3000 
# This is a gate for IP phones.
# 000: 4b 4c 55 47 00 00 00 4a 00 03 00 01 00 00 00 42   KLUG...J.......B
# 010: 02 04 49 50 2d 53 77 41 20 56 30 31 2e 32 38 00   ..IP-SwA V01.28.
# 020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
if (match(string: r, pattern: 'KLUG\0*IP-SwA V*\0\0\0\0*'))
{
  register_service(port: port, proto: 'hg-gate');
   report_and_return(port: port, data: 'An HG gate for IP phones is running on this port.'); 
 return 1;
}

# Contrib from Lior Rotkovitch
# 00: 32 32 30 20 41 78 69 73 20 44 65 76 65 6c 6f 70    220 Axis Develop
# 10: 65 72 20 42 6f 61 72 64 20 4c 58 20 72 65 6c 65    er Board LX rele
# 20: 61 73 65 20 32 2e 31 2e 30 20 28 4a 75 6c 20 32    ase 2.1.0 (Jul 2
# 30: 37 20 32 30 30 34 29 20 72 65 61 64 79 2e 0a 35    7 2004) ready..5
# 40: 30 33 20 42 61 64 20 73 65 71 75 65 6e 63 65 20    03 Bad sequence 
# 50: 6f 66 20 63 6f 6d 6d 61 6e 64 73 2e 0d 0a          of commands...
if (match(string: r, pattern: '220 Axis Developer Board*ready*503 Bad sequence*'))
{
 report_service(port: port, svc: 'axis-developer-board');
 return 1;
}

# From Guenther Konrad
# 00: 68 6f 73 74 73 2f 4b 4c 55 30 31 30 36 65 0a 4b    hosts/KLU0106e.K
# 10: 4c 55 30 31 30 35 65 0a                            LU0105e.
if (substr(r, 0, 5) == 'hosts/')
{
 v = split(substr(r, 6), sep: '\n', keep: 0);
 if (max_index(v) == 2)
 {
  register_service(port: port, proto: 'ibm-pssp-spseccfg');
  rep = 'IBM PSSP spseccfg is running on this port.\n';
  if (strlen(v[0]) > 0)
   rep = strcat(rep, 'It reports that the DCE hostname is "', v[0], '".\n');
  else
   rep += 'DCE is not configured on this host\n';
  rep = strcat(rep, 'The system partition name or the local hostname is "', v[1], '".');
  report_and_return(port: port, data: rep);
  return 1;
 }
}
# Port 4466
if (r == '\x30\x20\x39\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
{
 register_service(port: port, proto: 'ibm-pssp-switchtbld');
 report_and_return(port: port, data: 'IBM PSSP switchtbld is running on this port.\nFor more information on PSSP, read :\nhttp://publib.boulder.ibm.com/infocenter/clresctr/index.jsp?topic=/com.ibm.cluster.pssp.doc/pssp35/am0dgmst/am0dgmst180.html');
 return 1;
}

# 0x00: 15 03 00 00 02 02 0A ....... 
if (r == '\x15\x03\x00\x00\x02\x02\x0A' ||
    r == '\x15\x03\x01\x00\x02\x02\x0A' )
{
 report_and_return(port: port, data: 
'An unknown server is running on top of SSL/TLS on this port.
You should change find_service preferences to look for 
SSL based services and restart your scan.
');
 register_service(port: port, proto: 'ssl');
 return 1;
}

# 01 00 08 00 00 00 0a 8b f2 58 ca
# 01 00 08 00 00 00 0a 1d 0d 91 84
# 01 00 08 00 00 00 0a cf 99 84 25 ff 00 1e 00 1c 49 6e 76 61 6c 69 64 20 70 61 63 6b 65 74 20 77 69 74 68 20 74 79 70 65 20 31 32 39
# 01 00 08 00 00 00 0a 32 54 b0 a5
if (r_len > 7 && substr(r, 0, 6) == '\x01\x00\x08\x00\x00\x00\x0a')
{
 # Let's use the same name as Amap because of external_svc_ident.nasl
 register_service(port: port, proto: 'apache-tomcat-connector_ajp12');
 report_and_return(
  port: port,
  data:string(
    "The remote service is a Webapp Connector (also known as a WARP\n",
    "Connector), a connector component typically associated with older\n",
    "versions of Apache Tomcat that communicates with a web connector\n",
    "via the WARP protocol.\n"
  )
 );
 return 1;
}

# Should be caught by find_service1.nasl, I add this in case it did not
# answer to GET / ...
if (match(string: r, pattern: 'GPSD,E=?,*'))
{
 register_service(port:port, proto:"gpsd");
 report_and_return(port:port, data:"gpsd is running on this port.");
 return 1;
}

if (r == 'ERR password required\r\n' 
 && rget == 'ERR password required\r\nERR password required\r\n')
{
 register_service(port: port, proto: 'fli4l-imonc');
 report_and_return(port: port, data: 'imonc might be running on this port.'); 
 return 1;
}

# Does not answer to GET, only to HELP
if (r == '\x06\x00\x00\x00\x00\x00\x1a\x00\x00\x00')
{
 register_service(port: port, proto: 'mldonkey-gui');
 report_and_return(port: port, data: 'MLDonkey is running on this port (GUI access).'); 
 return 1; 
}

# From Dave Hellman
# Runs on port 900
if (r == '\x12\x00\x00\x80\x01\x10\xDC\x8A\x01\x00\x00\x00\x00\x04\x00\x00\x00\x41\x27\x07\x80\x00')
{
 register_service(port: port, proto: 'quest-intrust');
 report_and_return(port: port, data: 'Intrust (from Quest software) is running on this port.'); 
 return 1; 
}

# <html>
# <head><title>400 Bad Request</title></head>
# <body bgcolor="white">
# <center><h1>400 Bad Request</h1></center>
# <hr><center>nginx/0.7.65</center>
# </body>
# </html>
if (match(string: r, pattern: '<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor="*">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/*</center>\r\n</body>\r\n</html>\r\n'))
{
  register_service(port: port, proto: 'www');
  report_and_return(port: port, data: 
'nginx is running on this port.
This web server should have been detected earlier; increase the network
timeout and/or decrease the parallelism.');
  return 1;
}

# If you do not want to "double check", uncomment the next two lines
# if (! r0) set_unknown_banner(port: port, banner: r);
# return 1;

########################################################################
#                   **** WARNING ****                                  #
# Do not add anything below unless it should handled by find_service   #
# or find_service1 or find_service_3digits                             #
# The exception is qotd -- look at the bottom of the file              #
########################################################################


########################################################################
# All the following services should already have been identified by    #
# find_service1.nasl or find_service1.nasl; anyway, we double check in #
# case they failed...                                                  #
########################################################################

# See http://www.varnish-cache.org/
# 101 32
# all commands are in lower-case.
# (the first number appears to be a code, e.g. 200 for OK; the 2nd is the 
# length of the answer)
if (match(string: r, pattern: '101 *\nall commands are in lower-case.\n*'))
{
  register_service(port: port, proto: 'varnish_mngt');
  report_and_return(port: port, data: "Varnish Management is running on this port.");
  return 1;
}

# Veritas Backup Exec Remote Agent (6103/tcp)
if (r == '\xf6\xff\xff\xff\x10' ||
    r == '\xF6\xFF\xFF\xFF\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' )
{
  register_service(port: port, proto: "backup_exec");
  report_and_return(port: port, data: "Veritas Backup Exec Remote Agent seems to be running on this port.");
  return 1;
}

if (r == 'HELP\r\n\r\n')
{
 register_service(port: port, proto: 'echo');
 return report_and_return(port:port, data: 'Echo "simple TCP/IP service" is running on this port.');
}

# Spamd (port 783) - permissive Regex, just in case
if (r =~ '^SPAMD/[0-9.]+ [0-9]+ Bad header line:')
{
 register_service(port:port, proto:"spamd");
 return report_and_return(port:port, data:"A SpamAssassin daemon is running on this port.");
}

# SOCKS5
if (strlen(r) >= 4 && ord(r[0]) == 5 && ord(r[1]) <= 8 && ord(r[2]) == 0 && ord(r[3]) <= 4 && ord(r[1]) == strlen(r) - 2)
{
  register_service(port: port, proto: "socks5");
  return report_and_return(port: port, data: "A SOCKS5 server seems to be running on this port.");
}

# SOCKS4
if (strlen(r) >= 3 && ord(r[0]) == 0 && ord(r[1]) >= 90 && ord(r[1]) <= 93)
{
  register_service(port: port, proto: "socks4");
  return report_and_return(port: port, data: "A SOCKS4 server seems to be running on this port.");
}

if (egrep(pattern:"^\+OK.*POP2.*", string:r, icase:1) )
{
  register_service(port:port, proto:"pop2");
  return report_and_return(port: port, data: "A pop2 server seems to be running on this port.");
}

else if (egrep(pattern:"^\+OK.*POP.*", string:r, icase:1) )
{
  register_service(port:port, proto:"pop3");
  return report_and_return(port: port, data: "A pop3 server seems to be running on this port.");
}

# FTP - note that SMTP & SNPP also return 220 & 214 codes
if (egrep(pattern:"^220[- ].*FTP", string:r, icase: 1) ||
    egrep(pattern:"^214-? .*FTP", string: r, icase: 1) ||
    egrep(pattern:"^220[- ].*CrownNet", string: r, icase: 1) ||
    egrep(pattern:"^220 Axis.*Network Camera", string: r, icase: 1) ||
    (egrep(pattern:"^220 ", string:r) 
     && egrep(pattern: "^530 Please login with USER and PASS", string: r, icase: 1) )
   )
{
  banner = egrep(pattern:"^2[01][04]-? ", string: r);
  k = strcat("ftp/banner/", port);
  replace_kb_item(name: k, value: banner);
  register_service(port: port, proto: "ftp");
  return report_and_return(port: port, data: "An FTP server seems to be running on this port.");
}

# SMTP
if (egrep(pattern:"^220[ -].*(SMTP|mail)", string:r, icase: 1) ||
    egrep(pattern:"^214[ -].*(HELO|MAIL|RCPT|DATA|VRFY|EXPN)", string: r) ||
    egrep(pattern:"^220[ -].*OpenVMS.*ready", string: r) ||
    egrep(pattern:"^554 +E?SMTP ", string: r) ||
    egrep(pattern:"^421[ -].*SMTP", string: r))
{
  banner = egrep(pattern:"^[245][0-5][0-4][ -]", string: r);
  k = strcat("smtp/banner/", port);
  replace_kb_item(name: k, value: banner);
  register_service(port: port, proto: "smtp");
  return report_and_return(port: port, data: "An SMTP server seems to be running on this port.");
}

if ( '(gdb)\nerror, message' >< r ) 
{
  register_service(port:port, proto: "gdb");
  report_and_return(port: port, data: "A gdb remote debugger seems to be running on this port.");
  return 1;
}

# NNTP
if (egrep(pattern: "^200 .*(NNTP|NNRP)", string: r) ||
    egrep(pattern: "^100 .*commands", string: r, icase: 1))
{
  banner = egrep(pattern:"^200 ", string: r);
  if (banner)
  {
    k = strcat("nntp/banner/", port);
    replace_kb_item(name: k, value: banner);
  }
  register_service(port: port, proto: "nntp");
  return report_and_return(port: port, data: "An NNTP server seems to be running on this port.");
}

# SSH
banner = egrep(pattern: "^SSH-", string: r);
if (banner)
{
  register_service(port: port, proto: "ssh");
  return report_and_return(port: port, data: "An SSH server seems to be running on this port.");
}

# Contrib from Maarten
# 00: 0d 0a 44 65 73 74 69 6e 61 74 69 6f 6e 20 73 65 ..Destination se
# 10: 72 76 65 72 20 64 6f 65 73 20 6e 6f 74 20 68 61 rver does not ha
# 20: 76 65 20 53 73 68 20 61 63 74 69 76 61 74 65 64 ve Ssh activated
# 30: 2e 0d 0a 43 6f 6e 74 61 63 74 20 43 69 73 63 6f ...Contact Cisco
# 40: 20 53 79 73 74 65 6d 73 2c 20 49 6e 63 20 74 6f Systems, Inc to
# 50: 20 70 75 72 63 68 61 73 65 20 61 0d 0a 6c 69 63 purchase a..lic
# 60: 65 6e 73 65 20 6b 65 79 20 74 6f 20 61 63 74 69 ense key to acti
# 70: 76 61 74 65 20 53 73 68 2e 0d 0a vate Ssh...

if ("Destination server does not have Ssh activated" >< r)
{
 register_service(port: port, proto: "disabled-ssh");
 return report_and_return(port: port, data: "A disabled SSH service seems to be running on this port.");
}


# Auth
if (egrep(string: r, pattern:"^0 *, *0 *: * ERROR *:") )
{
  register_service(port: port, proto: "auth");
  return report_and_return(port: port, data: "An Auth/ident server seems to be running on this port.");
}

# Finger
if ((egrep(string: r, pattern: "HELP: no such user", icase: 1)) ||
    (egrep(string :r, pattern: ".*Line.*User.*Host", icase:1)) ||
    (egrep(string:r, pattern:".*Login.*Name.*TTY", icase:1)) ||
    '?Sorry, could not find "GET"' >< r ||
    'Login name: HELP' >< r  ||
    (('Time Since Boot:' >< r) && ("Name        pid" >< r) ))
{
  register_service(port: port, proto: "finger");
  return report_and_return(port: port, data: "A finger server seems to be running on this port.");
}

# HTTP
if (("501 Method Not Implemented" >< r) || (ereg(string: r, pattern: "^HTTP/1\.[01]")) || "action requested by the browser" >< r)
{
  register_service(port: port, proto: "www");
  return report_and_return(port: port, data: "A web server seems to be running on this port.");
}

# BitTorrent - no need to send anything to get the banner, in fact
if (r =~ "^BitTorrent protocol")
{
  register_service(port: port, proto: "BitTorrent");
  return report_and_return(port: port, data: "A BitTorrent server seems to be running on this port.");
}

# Jabber C2S and S2S servers return the same error and cannot be identified 
# precisely by this test only.
if (match(string: r, pattern: "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'*</stream:stream>", icase: 1) ||
# Jabber (http://www.jabber.org) detection (usually on 5222/tcp).
   "<stream:error>Invalid XML</stream:error>" >< r ||
# Oracle Messenger (Jabber) detection (usually on 5222/tcp,5223/tcp for TLS).
  "<stream:error>Connection is closing</stream:error></stream:stream>" >< r)
{
  register_service(port: port, proto: "jabber");
  return report_and_return(port: port, data: "A jabber server seems to be running on this port.");
}

# Zebra vty
if (r =~ "Hello, this is ([Zz]ebra|[Qq]uagga)")
{
  register_service(port: port, proto: "zebra");
  replace_kb_item(name: "zebra/banner/"+port, value: r);
  return report_and_return(port: port, data: "A zebra daemon is running on this port.");
}

# Zebra vty
if ("Vty password is not set" >< r)
{
  register_service(port: port, proto: "zebra-unconfigured");
  replace_kb_item(name: "zebra-unconfigured/banner/"+port, value: r);
  return report_and_return(port: port, data: "An unconfigured zebra daemon is running on this port.");
}

# IMAP4
if (
  egrep(pattern:"^\* *OK .* IMAP", string:r) ||
  egrep(pattern:"^\* *OK IMAP ", string:r)
)
{
  register_service(port: port, proto: "imap");
  replace_kb_item(name: "imap/banner/"+port, value: r);
  return report_and_return(port: port, data: "An IMAP server is running on this port.");
}

if ("cvs [pserver]" >< r ||
    "cvs [server aborted" >< r )
{
  register_service(port: port, proto: "cvspserver");
  return report_and_return(port: port, data: "A CVS pserver is running on this port.");
}

if ("@ABCDEFGHIJKLMNOPQRSTUV" >< r )
{
  register_service(port:port, proto: "chargen");
  return report_and_return(port: port, data: "A chargen server is running on this port.");
}

# This is an IRC bouncer!
if ( egrep(pattern:":Welcome!.*NOTICE.*psyBNC", icase:TRUE, string:r ) ) 
{
  register_service(port:port, proto: "irc-bnc");
  return report_and_return(port: port, hole: 1, data: "psyBNC seems to be running on this port.");
}

 if ( r =~ "\[BNC [0-9.]+" )
 { 
  register_service(port:port, proto: "BNC");
  return report_and_return(port: port, hole: 1, data: "A BNC proxy seems to be running on this port.");
 }

if ( "CCProxy Telnet Service Ready" >< r )
{
  register_service(port:port, proto: "ccproxy-telnet");
  report_and_return(port: port, data: "CCProxy (telnet) seems to be running on this port.");
  return 1;
}

if ( "CCProxy FTP Service" >< r )
{
  register_service(port:port, proto: "ccproxy-ftp");
  report_and_return(port: port, data: "CCProxy (ftp) seems to be running on this port.");
  return 1;
}
if ( "CCProxy " >< r  && "SMTP Service Ready" >< r )
{
  register_service(port:port, proto: "ccproxy-smtp");
  report_and_return(port: port, data: "CCProxy (smtp) seems to be running on this port.");
  return 1;
}

# 54 6F 6F 20 4D 61 6E 79 20 55 73 65 72 73 2E 20 Too Many Users.
# 50 6C 65 61 73 65 20 63 6F 6E 74 61 63 74 20 59 Please contact Y
# 6F 75 6E 67 7A 73 6F 66 74 20 66 6F 72 20 73 75 oungzsoft for su
# 70 70 6F 72 74 20 6F 66 20 6D 6F 72 65 20 75 73 pport of more us
# 65 72 73 2E                                     ers.
if (match(string: r, pattern: 'Too Many Users. Please contact Youngzsoft*'))
{
  register_service(port:port, proto: "ccproxy");
  report_and_return(port: port, data: "An overloaded CCProxy seems to be running on this port.");
  return 1;
}

if ( "CMailServer " >< r  && "SMTP Service Ready" >< r )
{
  register_service(port:port, proto: "cmailserver-smtp");
  report_and_return(port: port, data: "CMailServer (smtp) seems to be running on this port.");
  return 1;
}

# 0000000 30 11 00 00 00 00 00 00 d7 a3 70 3d 0a d7 0d 40
#          0 021  \0  \0  \0  \0  \0  \0   x   PS   p   =  \n   x  \r   @
# 0000020 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
#         \0  \0  \0  \0  \0  \0  \0  \0 001  \0  \0  \0 001  \0  \0  \0
# 0000040 00 00 00 00 02 00 00 00
#         \0  \0  \0  \0 002  \0  \0  \0
# 0000050
if ((r =~ '^\x30\x11\x00\x00\x00\x00\x00\x00') && (r_len == 40))
{
  register_service(port: port, proto: 'dameware');
  report_and_return(port: port, data: "Dameware seems to be running on this port.");
  return 1;
}

if ( strlen(r) > 4 )
{
  local_var l, ver;
  l = ord(r[0]) + (ord(r[1]) << 8) + (ord(r[2]) << 16);
  if (
    (
      # just the HIP or...
      strlen(r) == (l+4) ||
      # HIP + error packet
      strlen(r) > (l+4+4) && ord(r[l+4+4]) == 0xff
    ) && 
    ord(r[3]) == 0 && 
    ord(r[4]) > 0
  )
  {
    # A SpinxQL listener look a lot like MySQL but can be
    # differentiated by the auth_plugin_data field having
    # a constant value of \x01\x02\x03\x04\x05\x06\x07\x08
    local_var auth_plugin_data_index, auth_plugin_data;
    auth_plugin_data_index = stridx(r, '\x00', 5) + 5;
    auth_plugin_data = substr(r, auth_plugin_data_index, auth_plugin_data_index + 7);
    if (auth_plugin_data == '\x01\x02\x03\x04\x05\x06\x07\x08')
    {
      register_service(port:port, proto: "sphinxql");
      report_and_return(port:port, data: "A Sphinx search server SphinxQL listener is running on this port.");
      return 1;
    }

    # MySQL
    l = ord(r[4]);
    # nb: 'ver' denotes the start of the version string but includes
    #     other stuff after it.
    ver = substr(r, 5, l+5-1-1);
    if (ver =~ '^[0-9.]+\\.[0-9.]+\\.[0-9.]+')
    { 
      register_service(port: port, proto: 'mysql');
      report_and_return(port: port, data: "A MySQL server is running on this port.");
      return 1;
    }
    else if (ver =~ '^[0-9.]+\\.[0-9.]+-')
    { 
      register_service(port: port, proto: 'mysql_im');
      report_and_return(port: port, data: "A MySQL Instance Manager is running on this port.");
      return 1;
    }
  }
}

if ( '501 "Invalid command"' >< r && ereg(pattern:"^[0-9][0-9][0-9].+(MailSite|WorldMail) Mail Management Server .+ ready", string:r) )
{
  local_var vendor;
  register_service(port: port, proto: "mailma");
  if ("WorldMail " >< r) vendor = "WorldMail";
  else vendor = "MailSite";
  return report_and_return(port: port, data: vendor+"'s Mail Management Agent (MAILMA) seems to be running on this port.");
}

if ( egrep(pattern:"^[0-9][0-9][0-9][0-9]-NMAP \$Revision: .+Help", string:r) )
{
  register_service(port:port, proto: "novell_nmap");
  report_and_return(port: port, data:string("A Novell Network Messaging Application Protocol (NMAP) agent seems\r\nto be running on this port."));
  return 1;
}

if ( "Open DC Hub, version" >< r  && "administrators port" >< r )
{
  register_service(port:port, proto: "opendchub");
  report_and_return(port: port, data: "Open DC Hub Administrative interface (peer-to-peer) seems to be running on this port.");
  return 1;
}

if ( ereg(pattern:"^$MyNick ", string:r) )
{
  register_service(port:port, proto: "DirectConnect");
  report_and_return(port: port, data: "Direct Connect seems to be running on this port.");
  return 1;
}

# PPT protocol is documented here:
if (stridx(r, "PPT Can not negotiate,  client started the connection with") == 0)
{
  register_service(port:port, proto: "PPT");
  report_and_return(port: port, data: "An OPeNDAP Back End Server (BES) is listening on this port.");
  return 1;
}

# This should be handled by find_service1.nasl.
if ( ereg(pattern:"^RFB 00[0-9]\.00", string:r) )
{
  register_service(port:port, proto: "vnc");
  report_and_return(port: port, data: "A VNC server seems to be running on this port.");
  return 1;
}
if ( ereg(pattern:"^RFB 003\.889$", string:r) )
{
  register_service(port:port, proto: "ard");
  report_and_return(port: port, data: "Apple Remote Desktop is running on this port.");
  return 1;
}

if ( egrep(pattern:"^BZFS00", string:r) )
{
  register_service(port:port, proto:"bzFlag");
  report_and_return(port: port, data: "A bzFlag server seems to be running on this port.");
  return 1;
}

# Keep this before MSDTC!
if (r == '\x70\x63\x70\x00\x00\x02')
{
  register_service(port: port, proto: 'ekpd');
 report_and_return(port: port, data: 
"EKPD, a component of Seiko Epson Color Inkjet printing driver for Linux, 
is running on this port.");
  exit(0);
}

# MS DTC banner is longer that 3 bytes, when we properly handle null bytes
# This test is copied from find_service1, but sometimes, find_service1
# does not catch it.
if ((r_len == 5 || r_len == 6) && r[3] == '\0' && 
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0')
{
  register_service(port: port, proto: "msdtc");
  report_and_return(port: port, data: "An MSDTC server seems to be running on this port.");
  return 1;
}

# MS DTC (obsolete)
if (r_len == 3 && (r[2] == '\x10'||	# same test as find_service
                       r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  report_and_return(port: port, data: "An MSDTC server seems to be running on this port.");
  return 1;
}

# MA 2008-08-30 
# Taken from find_service1 -- for some reason, msdtc was missed at least once
# Examples:
# 00: 90 a2 0a 00 80 94 .. 
# 00: F8 2D 0B 00 00 16 .-.... 
if ((r_len == 5 || r_len == 6) && r[3] == '\0' && 
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0')
{
  register_service(port: port, proto: "msdtc");
  report_and_return(port: port, data: "An MSDTC server seems to be running on this port.");
  return 1;
}

if (r == 'GIOP\x01')
{
 register_service(port:port, proto:"giop");
 report_and_return(port: port, data: "A GIOP-enabled service is running on this port.");
 return 1;
}

# http://synergy2.sourceforge.net/
if ( r == '\x00\x00\x00\x0B\x53\x79\x6E\x65\x72\x67\x79\x00\x01\x00\x03' )
{
 register_service(port:port, proto:"synergy");
 report_and_return(port: port, data: "A Synergy server is running on this port.");
 return 1;
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if (match(string: r, pattern: '"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*'))
{
 register_service(port: port, proto: 'sieve');
 report_and_return(port: port, data: 'Sieve mail filter daemon seems to be running on this port.');
 return 1;
}

#
# xtris is a multiplayer tetris game.
#
# http://www.iagora.com/~espel/xtris/xtris.html
#
if ( hexstr(r) == "000000020114" )
{
 register_service(port: port, proto: 'xtris');
 report_and_return(port: port, data: 'An xtris game server is listening on this port.');
 return 1;
}

# Contrib from Roland Clobus,
#   http://mail.nessus.org/pipermail/nessus/2006-July/msg00116.html
# 0x00:  77 65 6C 63 6F 6D 65 20 74 6F 20 74 68 65 20 70  welcome to the p
# 0x10:  69 6F 6E 65 65 72 73 2D 6D 65 74 61 2D 73 65 72    ioneers-meta-ser
# 0x20:  76 65 72 20 76 65 72 73 69 6F 6E 20 31 2E 33 0A    ver version 1.3.
#
# nb: this will always be on port 5557/tcp according to Roland.
if ("welcome to the pioneers-meta-server version" >< r)
{
 register_service(port: port, proto: 'pioneers-meta-server');
 report_and_return(port:port, data:"A meta server for the game Pioneers is running on this port.");
 return 1;
}

# Contribution from Mark Phillips,
# 0x00: 02 80 02 82 70 62 04 82 6E 6F 6E 65 ....pb..none 
#
# http://www.zenoss.com/
if (r == raw_string(0x02, 0x80, 0x02, 0x82, "pb", 0x04, 0x82, "none"))
{
 register_service(port:port, proto:'zenhub');
 report = string(
  "A zenhub daemon appears to be running on this port. Zenhub is a\n",
  "component of the Zenoss network and systems monitoring application suite\n",
  "that serves as an intermediary connection for almost all Zenoss\n",
  "collection daemons to the Zeo and MySQL databases on the remote host."
 );
 report_and_return(port:port, data:report);
 return 1;
}

# See <http://www.faqs.org/docs/ZopeBook/ZEO.html>.
if (r == raw_string(0x00, 0x00, 0x00, 0x04, "Z303"))
{
 register_service(port:port, proto:'zss');
 report = string(
  "A ZEO Storage Server is listening on the remote host. Zope Enterprise\n",
  "Objects, or ZEO, is a system used for clustering and load-balancing web\n",
  "servers, and a ZEO Storage Server provides a centralized data store for\n",
  "ZEO clients."
 );
 report_and_return(port:port, data:report);
 return 1;
}

# Contribution from Ian Ward Comfort.
#
# http://www.sassafras.com/ 
if ("'QUIT','close KSQL session'" >< r)
{
 register_service(port:port, proto:'k2-keyserver');
 report = string(
  "A K2 KeyServer daemon is listening on this port. K2 is a toolkit for\n",
  "auditing and license management, and KeyServer is its central auditing\n",
  "and license server component.\n"
 );
 report_and_return(port:port, data:report);
 return 1;
}

if ('Argus running\n' == r)
{
 register_service(port:port, proto:'Argus');
 report_and_return(port:port, data:"Argus is running on the remote host.");
 return 1;
}

# Part of Versant Object Database, http://www.versant.com/
if (
  strlen(r) == 0x44 &&
  substr(r, 0, 3) == raw_string(0x01, 0x01, 0x00, 0x50) &&
  substr(r, 0x40, 0x43) == raw_string(0xff, 0xff, 0x8a, 0x6a)
)
{
 register_service(port:port, proto:'versant_sqlnw');
 report_and_return(port:port, data:"A Versant SQL Listener is running on the remote host.");
 return 1;
}

# Teamspeak, http://teamspeak.com/
#
# submitted by Arne Bracht.
if (stridx(r, '[TS]\r\ncommand overview:') == 0)
{
 register_service(port:port, proto:'teamspeak-tcpquery');
 report_and_return(port:port, data:"A TeamSpeak TCPQUERY server is listening on the remote host.");
 return 1;
}

# SupportWorks ITSM, http://www.hornbill.com/products/
#
# submitted by John Soltys.
if ("Supportworks Mail Server ready <" >< r)
{
 register_service(port:port, proto:'swmailservice');
 report_and_return(port:port, data:"The remote service is a Supportworks Mail Server.");
 return 1;
}
if ("Supportworks Helpdesk ready <" >< r)
{
 register_service(port:port, proto:'swserverservice');
 report_and_return(port:port, data:"The remote service is the Supportworks main server, to which\nSupportworks clients connect.");
 return 1;
}
if ("Support-Works Messenger Server " >< r)
{
 register_service(port:port, proto:'swmessengerservice');
 report_and_return(port:port, data:"The remote service is the Supportworks Messenger, which is responsible\nfor popping up messages on Windows workstations.");
 return 1;
}

# Lexmark / Dell Laser Printer.
#
# Submitted by Daniel Frazier.
if (stridx(r, 'LXK: \r\nbad command: HELP') == 0)
{
 register_service(port:port, proto:'lexmark_admin');
 report_and_return(port:port, data:"The admin service for a Lexmark printer is listening on this port.");
 return 1;
}

# m-Router
#
# Submitted by David.
if (r == ' \x00\x02\x00')
{
 register_service(port:port, proto:'mrouter');
 report_and_return(port:port, data:"The remote service appears to be m-Router, used for connecting a\nmobile device to the computer.");
 return 1;
}

if (r == '220\r\n')
{
  register_service(port:port, proto: "220backdoor");
  return 1;
}

# HP Printer.
#
# nb: these banners can also be seen as spontaneous banners or 
#     responses to GET requests.
if (
  stridx(r, '@PJL USTATUS TIMED\r\n') == 0 ||
  stridx(r, '@PJL USTATUS DEVICE\r\n') == 0
)
{
  register_service(port:port, proto:"appsocket");
  report_and_return(port:port, data:'A Socket API service, commonly associated with print servers, is\nlistening on this port.');
  return 1;
}

# CrashPlan.
#
# Submitted by David Franco.
if ("com.code42.messaging.security.DHPublicKeyMessage" >< r)
{
  register_service(port:port, proto:"crashplan");
  report_and_return(port:port, data:'The CrashPlan backup engine service is listening on this port.');
  return 1;
}

# Cirrato client
# http://www.cirrato.com/how-it-works/faq/#what-network-ports-need-to-be-open-for-cirrato-to-work
#
# Submitted by Peter Eriksson
if ("Cirrato Client " >< r)
{
  register_service(port:port, proto:"cirrato_client");
  report_and_return(port:port, data:'A Cirrato client is listening on this port.');
  return 1;
}

# ncacn_http
#
# nb: this will generally be picked up by find_service.nasl.
if (substr_at_offset(str:r, blob:"ncacn_http/1.", offset:0))
{
  if ( port == 593 )
  {
    register_service(port:port, proto:"http-rpc-epmap");
    report_and_return(port:port, data:'An http-rpc-epmap server is running on this port.');
  }
  else
  {
    register_service(port:port, proto:"ncacn_http");
    report_and_return(port:port, data:'An ncacn_http server is running on this port.');
  }
  return 1;
}

# Taken from find_service1 -- for some reason it was missed at least once.
if((r_len > 8) && (substr(r,0,7) == '\x2E\x4E\x45\x54\x01\x00\x02\x00'))
{
  register_service(port: port, proto: "remoting_tcp");
  # nb: let dotnet_remoting_services_detect.nasl report it.
  return 1;
}

# Seems to be slow
if ( '************' >< r && 
    '  Telnet Administration \r\n' >< r && ' SAP J2EE Engine v' >< r)
{
  register_service(port: port, proto: 'sap-j2ee-telnet-admin');
  report_and_return(port: port, data: 
"A SAP J2EE engine administration service (Telnet) is running on this port.");
  return 1;
}

# Taken from find_service -- for some reason it was missed at least once.
if (r =~ "^220 " && "VMware Authentication Daemon" >< r)
{
  register_service(port: port, proto: 'vmware_auth');
  report_and_return(port: port, data: "A VMware authentication daemon is running on this port.");
  return 1;
}

#
# Keep verity-k2 at the end of the list, as it may generate false detection
#
if (r == '-1101\0')
{
 register_service(port:port, proto:'verity-k2');
 report_and_return(port:port, data:'A Verity K2 Service (Search, Admin or Index), commonly installed\nwith ColdFusion MX, is running on this port.');
 return 1;
}

#
# Keep qotd at the end of the list, as it may generate false detection
#
if ( r =~ '^"[^"]+"[ \t\r\n]+[^+*@(){}\\\\/@0-9_]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' 
#r =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$'
 || egrep(pattern: "^[A-Za-z. -]+\([0-9-]+\)", string: r) )
 {
  register_service(port:port, proto: "qotd");
  report_and_return(port: port, data: "qotd seems to be running on this port");
  return 1;
 }

 if ( r == 'A\x01\x02\x00' )	# This is already detected by find_service.nasl
 {
  register_service(port:port, proto: "smux");
  report_and_return(port: port, data: "An SNMP Multiplexer (smux) seems to be running on this port");
  return 1;
 }

 if ( "ASSOC" >< r &&
      "ATTRIB" >< r &&
      "AT" >< r &&
      "BREAK" >< r )
  {
  register_service(port:port, proto: "possibly-ciscoworks-ipm");
  return 1;
  }
  
 #0000   14 00 01 00 0d 0a 01 37 51 c3 00 00 08 00 00 00  .......7Q.......
 #0010   00 69 43 00                                      .iC.
 if(strlen(r) == 20 && hex2raw(s: "140001000d0a013751c300000800000000694300") >< r )
 {
  register_service(port: port, proto: "Fujitsu-systemcast-deployment-server");
  report_and_return(port: port, data: "Fujitsu systemcast deployment server seems to be running on this port.");
  return 1;
 }

 # Measuresoft ScadaPro
 if ("-1,8002" >< r && port == 11234)
 {
   register_service(port: port, proto: 'scadapro-ipc');
   report_and_return(port: port, data: 'Measuresoft ScadaPro IPC service (service.exe) seems to be running on this port.');
   return 1; 
 }

 return 0;
}

#-------------------------------------------------------------------------------------------------------------#

if ( NASL_LEVEL < 3203 )
{
 #
 # Nessus 2.x, 3.0.x
 #
 port = get_kb_item("Services/unknown");
 if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

 # Check only mute services?
 r0 = get_unknown_banner(port: port, dontfetch: 1);
 if (!isnull(r0) && identify(r:r0, port:port) ) exit(0);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);

 send(socket: soc, data: 'HELP\r\n');
 r = recv(socket:soc, length:4096);
 close(soc);

 if (isnull(r)) exit(0);
 rget = get_kb_banner(port:port, type:'get_http');

 set_kb_banner(port:port, type: 'help', banner: r);
 identify(r:r, port:port, rget:rget);


 ########################################################################
 #             Unidentified service                                     #
 ########################################################################
 if (isnull(r0)) set_unknown_banner(port: port, banner: r);
}
else
{
 # Nessus 3.2.x
 ports = get_kb_list("Services/unknown");
 if ( isnull(ports) ) exit(0); 
 ports = make_list(ports);

 foreach port ( ports )
 {
  if ( get_port_state(port) && service_is_unknown(port: port)) 
  {

 	r0 = get_unknown_banner(port: port, dontfetch: 1);
 	if (isnull(r0) || !identify(r:r0, port:port) ) 
		port_push(port);
  }
 }

 for ( i = 0 ; i < MAX_SIMULT_CONNECTIONS ; i ++ )
	if ( port_new() == FALSE ) break;

 while ( select() != 0 ) usleep(5000);

 foreach port ( keys(g_banners) ) 
 {
  r = g_banners[port];
  if ( isnull(r) ) continue;
  set_kb_banner(port: port, type:'help', banner: r);
  rget = get_kb_banner(port: port, type:'get_http');

  identify(r:r, port:port, rget:rget);
  if (isnull(get_unknown_banner(port: port, dontfetch: 1))) set_unknown_banner(port: port, banner: r);
 } 
}
