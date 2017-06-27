#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(14773);
 script_version ("$Revision: 1.58 $");
 script_cvs_date("$Date: 2011/08/16 01:49:38 $");
 
 script_name(english:"Service Detection: 3 ASCII Digit Code Responses");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin performs service detection." );
 script_set_attribute(attribute:"description", value:
"This plugin is a complement of find_service1.nasl.  It attempts to
identify services that return 3 ASCII digits codes (ie: FTP, SMTP,
NNTP, ...)" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Identifies services that return 3 ASCII digits codes");
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl"); # cifs445.nasl 

 # "rpcinfo.nasl", "dcetest.nasl"

# Do *not* add a port dependency  on "Services/three_digits"
# find_service2 must run after this script even if there are no
# '3 digits' services

 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if ( get_kb_item("global_settings/disable_service_discovery") )
 exit(0, "Service discovery is disabled.");


port = get_kb_item("Services/three_digits");
if (! port) exit(0, "No '3digits' service has been found.");
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
if (! service_is_unknown(port: port))
 exit(0, "The service on port "+port+" has already been identified.");	

if (thorough_tests) retry = 3;
else retry = 1;

global_var retry;

function read_answer(socket)
{
  local_var	r, answer, i;

  repeat
  {
   for (i = 0; i <= retry; i ++)
   {
    r = recv_line(socket: socket, length: 4096);
    if (strlen(r) > 0) break;
   }
   answer += r;
  }
  until (! r || r =~ '^[0-9]{3}[^-]' || strlen(answer) > 1000000);
  return answer;
}

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");
spontaneous = read_answer(socket: soc);
banner = spontaneous;

if (banner)
  set_kb_banner(port: port, type: "spontaneous", banner: banner);
else
  debug_print('Banner is void on port ', port, ' \n');

# 500 = Unknown command
# 502 = Command not implemented

# If HELP works, it is simpler than anything else
send(socket: soc, data: 'HELP\r\n');
help = read_answer(socket: soc);
if (help)
{
  set_kb_banner(port: port, type: "help", banner: help);
  if (! banner) banner = help; # Not normal, but better than nothing
}    

if (ereg(string: help, pattern: '^554 +E?SMTP '))
{
 # Overloaded MTA? Unimplemented HELP?
 report_service(port: port, svc: 'smtp', banner: banner);
 if (banner =~ '^[45][0-9][0-9][ -]')
 {
  set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
  if (port == 25)
   set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 }
 exit(0);
}

if (help !~ '^50[0-9]')
{
 if ("ARTICLE" >< help || "NEWGROUPS" >< help || "XHDR" >< help || "XOVER" >< help)
 {
  report_service(port:port, svc: 'nntp', banner: banner);
  exit(0);
 }
 # nb: this must come before FTP recognition.
 if (
  egrep(string:banner, pattern:"^220.*HylaFAX .*Version") ||
  egrep(string:help,   pattern:"^220.*HylaFAX .*Version")
 )
 {
  report_service(port: port, svc: 'hylafax', banner: banner);
  exit(0);
 }
 # MQ Broker used by Sun's Java Message Service (tcp 7676 by default).
 #
 # nb: this must come before FTP recognition.
 if (
   banner &&
   stridx(banner, "101 ") == 0 &&
  (
   stridx(banner, "imqbroker") == 4 ||
   # nb: DSBroker is a rebranded Sun imqbrokerd as used by Xerox DocuShare.
   stridx(banner, "DSBroker ") == 4 ||
   string("portmapper tcp PORTMAPPER ", port) >< banner
  )
 )
 {
  register_service(port:port, proto:"imqbrokerd");
  security_note(port:port, data:"A Message Queue broker is listening on this port.");
  exit(0);
 }
 # Spontaneous banner:
 #   000 Chat Server v3.4.9
 #   001 LOGIN?
 if (banner && stridx(banner, '000 Chat Server v') == 0)
 {
   register_service(port:port, proto:"simmcomm_chat");
   security_note(port:port, data:"SCI Photo Chat Server is listening on this port.");
   exit(0);
 }
 if ( "220 Sharp - NetScan Tool" >< banner )
 {
  report_service(port: port, svc: 'ftp', banner: banner);
  exit(0);
 }
 if ("PORT" >< help || "PASV" >< help)
 {
  report_service(port:port, svc: 'ftp', banner: banner); 
  exit(0);
 }
 # Code from find_service2.nasl
 if (help =~ '^220 .* SNPP ' || egrep(string: help, pattern: '^214 .*PAGE'))
 {
   report_service(port: port, svc: 'snpp', banner: banner);
   exit(0);
 }
 if (egrep(string: help, pattern: '^214-? ') && 'MDMFMT' >< help)
 {
  report_service(port: port, svc: 'hylafax-ftp', banner: banner);
  exit(0);
 }
 if (egrep(pattern:"^200.*Citadel(/UX| server ready)", string:banner) )
 {
  register_service(port:port, proto:"citadel/ux");
  security_note(port:port, data:"A Citadel server is running on this port");
  exit(0);
 }
 # http://tptest.sourceforge.net/
 if (egrep(pattern:"^200.*vmajor=[0-9]+;vminor=[0-9]+;cookie=[0-9]+", string:banner) )
 {
  register_service(port:port, proto:"tptestser");
  security_note(
    port:port, 
    data:string(
      "The remote service is a TPTEST server, used for measuring Internet\n",
      "bandwidth."
    )
  );
  exit(0);
 }
}

send(socket: soc, data: 'HELO mail.nessus.org\r\n');
helo = read_answer(socket: soc);
if (helo) set_kb_banner(port: port, type: 'helo', banner: helo);

if ( egrep(string: helo, pattern: '^250'))
{
 report_service(port:port, svc: 'smtp', banner: banner);
 exit(0);
}

send(socket: soc, data: 'LHLO mail.nessus.org\r\n');
lhlo = read_answer(socket: soc);
if (lhlo) set_kb_banner(port: port, type: 'lhlo', banner: lhlo);

if ( egrep(string: lhlo, pattern: '^250'))
{
 report_service(port:port, svc: 'lmtp', banner: banner);
 exit(0);
}


send(socket: soc, data: 'DATE\r\n');
date = read_answer(socket: soc);
if (date) set_kb_banner(port: port, type: 'date', banner: lhlo);

if (date =~ '^111[ \t]+2[0-9]{3}[01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]')
{
 report_service(port: port, svc: 'nntp', banner: banner);
 exit(0);
}


if (
  help == '514 Authentication required.\r\n' &&
  helo == help &&
  date == help
)
{
  req = string("AUTHENTICATE ", SCRIPT_NAME, "\r\n");
  send(socket: soc, data:req);
  res = read_answer(socket: soc);
  if (!isnull(res) && stridx(res, '551 Invalid hexadecimal encoding.  Maybe you tried') == 0)
  {
    register_service(port:port, proto:"tor_cp");
    security_hole(
      port:port, 
      data:string(
        "The remote service appears to be a Tor control port that allows\n",
        "connections, once authenticated, to control the associated Tor\n",
        "process."
      )
    );
    exit(0);
  }
}



# Code from find_service2.nasl:
# SNPP, HylaFAX FTP, HylaFAX SPP, agobot.fo, IRC bots, WinSock server,
# Note: this code must remain in find_service2.nasl until we think that
# all find_service1.nasl are up to date
#

if (egrep(pattern:"^220 Bot Server", string: help) ||
     raw_string(0xb0, 0x3e, 0xc3, 0x77, 0x4d, 0x5a, 0x90) >< help)
{
 report_service(port:port, svc:"agobot.fo", banner: banner);
 exit(0);
}
if ("500 P-Error" >< help && "220 Hello" >< help)	# or banner?
{
 report_service(port:port, svc:'unknown_irc_bot', banner: banner);
 exit(0);
}
if ("220 WinSock" >< help)	# or banner?
{
 report_service(port:port, svc:'winsock', banner: banner);
 exit(0);
}

close(soc); soc = NULL;

# Try poppasswd
if (egrep(pattern:"^200 .*(Password service|PWD Server|poppassd)", string:banner)) {
  report_service(port:port, svc:"pop3pw", banner:banner);
  exit(0);
}
if (banner && substr(banner, 0, 3) == '200 ' && supplied_logins_only == 0 )
{
 soc = open_sock_tcp(port);
 if (soc)
 {
  banner = read_answer(socket: soc);
  send(socket:soc, data:strcat('USER ',rand_str(length:8), '\r\n')); 
  r = read_answer(socket: soc);
  if (strlen(r) > 3 && substr(r, 0, 3) == '200 ')
  {
   send(socket:soc, data:strcat('PASS ', rand_str(length:8), 'r\n')); 
   r = read_answer(socket: soc);
   if (strlen(r) > 3 && substr(r, 0, 3) == '500 ')
   {
    report_service(port:port, svc:"pop3pw", banner:banner);
    close(soc);
    exit(0);
   }
  }
  close(soc);
 }
}

# MA 2006-09-14: Not tested against a printer yet
# I don't know if one of the probes above does not trigger against 
# this mysterious menu.
# I don't think that it should be moved before the other probes because:
# 1) it is quite rare & may be slow
# 2) some "anonymous FTP" servers do not require login and will answer to DIR
#
# ftp> dir
# 200 Command OK.
# 150 Open ASCII Mode Connection.
# 200 CONFIG
# 200 RESET
# 200 DEFAULTC
# 200 PSINF
# 200 SETIP
# 200 PASSRESET
# 226 Transfer complete.
# ftp> 

if (experimental_scripts)
{
r2 = '';
soc = open_sock_tcp(port);
if (soc)
{
 banner = read_answer(socket: soc);
 port2 = ftp_pasv(socket: soc);
 if (port2)
 {
  soc2 = open_sock_tcp(port2);
  if (soc2)
  {
   send(socket: soc, data: 'LIST\r\n\r\n');	# Or DIR??
   r = read_answer(socket: soc);
   if (strlen(r) > 3 && substr(r, 0, 3) == '150 ')
   {
    r2 = recv(socket: soc2, length: 2048);
    r = read_answer(socket: soc);
    if ("200 CONFIG" >< r2 && "200 RESET" >< r2 && "200 PSINF" >< r2)
    {
      report_service(port:port, svc:"print-server", banner:banner);
      exit(0);
    }
   }
   close(soc2);
  }
 }
 send(socket:soc, data: 'QUIT\r\n\r\n');
 # read_answer(socket: soc);
 close(soc);
}
}	# if experimental_scripts


# MA 2008-08-25: I prefer to be cautious and not use a generic RE 
# like '^5[0-9][0-0[ -]'
# Currently, this matches dictd
# Port :   2628
# Type :   spontaneous
# Banner : 
# 0x00:  35 33 30 20 61 63 63 65 73 73 20 64 65 6E 69 65    530 access denie
# 0x10:  64 0D 0A                                           d..
#
if (spontaneous =~ '^530[ -] *access denied')
{
  register_service(port: port, proto: '530_access_denied');
  exit(0);
}

# Give it to find_service2 & others
register_service(port: port, proto: 'unknown');
if (banner) set_unknown_banner(port: port, banner: banner);

exit(0); # Disable the warning below
if (report_paranoia > 1)
{
 security_warning(port: port, data: 
'Although this service answers with 3 digit ASCII codes
like FTP, SMTP or NNTP servers, Nessus was unable to identify it.

This is highly suspicious and might be a backdoor; in this case, 
your system is compromised and an attacker can control it remotely.

** If you know what it is, consider this message as a false alert
** and please report it to the Nessus team.

Solution : disinfect or reinstall your operating system
Risk factor : High');
}
