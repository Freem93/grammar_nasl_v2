#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11933);
 script_version("$Revision: 1.128 $");
 script_cvs_date("$Date: 2017/01/19 04:19:04 $");

 script_name(english:"Do not scan printers");
 script_summary(english:"Exclude printers from scan");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a fragile device and will not be
scanned.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a network printer, multi-function
device, or other fragile device. Such devices often react very poorly
when scanned. To avoid problems, Nessus has marked the remote host as
'Dead' and will not scan it.");
 script_set_attribute(attribute:"solution", value:
"If you are not concerned about such behavior, enable the 'Scan
Network Printers' setting under the 'Do not scan fragile devices'
advanced settings block and re-run the scan. Or if using Nessus 6,
enable 'Scan Network Printers' under 'Fragile Devices' in the Host
Discovery section and then re-run the scan.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 # script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"no");

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 # Or maybe a "scan option" family?
 script_dependencie("dont_scan_settings.nasl", "fqdn_sys.nasl", "snmp_settings.nasl");
 exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("telnet_func.inc");
# We have to keep the old HTTP API
include("http_func.inc");
include("snmp_func.inc");

global_var tcp_sockets;
if ( islocalhost() ) exit(0);

function init_tcp()
{
 local_var i;
 local_var soc;
 local_var limit;
 local_var flag;
 local_var keys;

 if ( NASL_LEVEL >= 3005 )
 {
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
 {
  if ( ! get_port_state(_FCT_ANON_ARGS[i]) ) continue;
  soc = open_sock_tcp(_FCT_ANON_ARGS[i], nonblocking:TRUE);
  if ( soc ) tcp_sockets[_FCT_ANON_ARGS[i]] = soc;
 }

 limit = unixtime() + get_read_timeout();
 keys = keys(tcp_sockets);
 while ( unixtime() < limit )
 {
  for ( i = 0 ; i < max_index(keys) ; i ++ )
  {
   if ( ! socket_ready(tcp_sockets[keys[i]]) ) flag ++;
  }
  if ( flag == 0 ) break;
  usleep(5000);
 }

  for ( i = 0 ; i < max_index(keys) ; i ++ )
  {
   if ( socket_ready(tcp_sockets[keys[i]]) <= 0 || socket_get_error(tcp_sockets[keys[i]]) != NOERR ) {
	close(tcp_sockets[keys[i]]);
	tcp_sockets[keys[i]] = NULL;
   }
  }
 }
 else
 {
  # Nessus 2.x
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
  tcp_sockets[keys[i]] = open_sock_tcp(_FCT_ANON_ARGS[i]);
 }
}

if ( get_kb_item("Scan/Do_Scan_Printers" ) ) exit(0);

i = 0;
printers[i++] = "Brother NC";
printers[i++] = "Canon LBP";
printers[i++] = "Canon iR";
printers[i++] = "FAST-KYO-TX";
printers[i++] = "FastPort II Model MIL-P3720";
printers[i++] = "Fiery";
printers[i++] = "Generic 28C-1";
printers[i++] = "Generic 30C-1";
printers[i++] = "HP ETHERNET MULTI-ENVIRONMENT";
printers[i++] = "IBM Infoprint";
printers[i++] = "JETDIRECT";
printers[i++] = "KONICA MINOLTA bizhub ";
printers[i++] = "KYOCERA MITA Printing";
printers[i++] = "KYOCERA Printer";
printers[i++] = "Konica IP Controller";
printers[i++] = "Lantronix EPS1";
printers[i++] = "Lantronix MSS100";
printers[i++] = "Lantronix MPS100";
printers[i++] = "LaserJet";
printers[i++] = "Lexmark";
printers[i++] = "Muratec F-";
printers[i++] = "Muratec MFX-";
printers[i++] = "NetQue";
printers[i++] = "Network Printer";
printers[i++] = "OKI OkiLAN";
printers[i++] = "PrintNet Enterprise";
printers[i++] = "Printek Network Interface";
printers[i++] = "RICOH Network Printer";
printers[i++] = "Samsung 9330";
printers[i++] = "TGNet";
printers[i++] = "TOSHIBA e-STUDIO";
printers[i++] = "TallyGenicom";
printers[i++] = "WorkCentre Pro";
printers[i++] = "XEROX";
printers[i++] = "ZebraNet PrintServer";
printers[i++] = "ZebraNet Wired PS";
# Note: not a printer, but a one off fragile device
printers[i++] = "APC Web/SNMP Management Card";
printers[i++] = "Integrated PrintNet Enterprise Version";
# A manageable switch
printers[i++] = "DGS-1210-48";

i = 0;
oids[i++] = "1.3.6.1.2.1.1.1.0"; # sysDescr.0
oids[i++] = "1.3.6.1.2.1.1.4.0"; # sysContact.0

printers_re = make_array();
printers_re["^AXIS ([0-9][^ ]+) Network Print Server"] = "an AXIS $1 Printer";
printers_re["^Canon Network Multi-PDL Printer Board.*"] = "a Canon Network Multi-PDL Printer Board";
printers_re["^Canon (MF[0-9][^ ]+) Series"] = "a Canon $1 Series Printer";
printers_re["^MF series printer"] = "a Canon MF Series Printer";
printers_re["(Dell (Color )?Laser Printer)"] = "a $1";
printers_re["^(Dell [0-9]+(cn?|cdn|cnw))[; ].+Engine"] = "a $1 Color Laser Printer";
printers_re["^(Dell [0-9]+dn?)[; ].+Engine"] = "a $1 Laser Printer";
printers_re["^D-Link (DP-[0-9][^ ]+) Print Server"] = "a D-Link $1 print server";
printers_re["^Panasonic (DP-[A-Z0-9]+)"] = "a Panasonic $1 Digital Imaging System";
printers_re["^Samsung ((CL[PX]|ML|SCX)-[0-9][0-9_]+)( Series|; OS )"] = "a Samsung $1 Series Printer";
printers_re["^SHARP ((AR|MX)-[^ ]+)$"] = "a Sharp $1 Printer";
printers_re["^Thermal Label Printer Intermec ((EasyCoder )?\S+)"] = "an Intermec $1 Printer";

sysobjids = make_array();
sysobjids["1.3.6.1.4.1.11.2.3.9.1"] = "an HP JetDirect printer";
sysobjids["1.3.6.1.4.1.11.2.3.9.2"] = "an HP plotter";
sysobjids["1.3.6.1.4.1.11.2.3.9.4"] = "an HP LaserJet printer";
sysobjids["1.3.6.1.4.1.171.11.10.1"] = "a D-Link print server";
sysobjids["1.3.6.1.4.1.236.11.5.1"] = "a Dell or Samsung printer";
sysobjids["1.3.6.1.4.1.4322.1.1"] = "a Muratec printer";

community = get_kb_item("SNMP/community");
port = get_kb_item("SNMP/port");
if ( community && port )
{
 soc = open_sock_udp (port);
 if (  soc )
 {
  foreach oid ( oids )
  {
  desc = snmp_request(socket:soc, community:community, oid:oid);
  if ( desc )
  {
   foreach printer (printers)
   {
     if ( tolower(printer) >< tolower(desc) )
     {
      set_kb_item(name: "Host/dead", value: TRUE);
      security_note(port: 0, extra:'\nSNMP reports it as ' + printer + '.\n');
      exit(0);
     }
    }

   foreach regex (keys(printers_re))
   {
     match = eregmatch(pattern:regex, string:desc);
     if ( match )
     {
      set_kb_item(name: "Host/dead", value: TRUE);

      name = printers_re[regex];
      if ("$1" >< name && match[1])
        name = str_replace(find:"$1", replace:match[1], string:name);

      security_note(port: 0, extra:'\nSNMP reports it as ' + name + '.\n');
      exit(0);
     }
    }
   }
  }

  # Check sysObjectID (1.3.6.1.2.1.1.2.0)
  desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.2.0");
  if ( desc )
  {
   foreach sysobjid (keys(sysobjids))
   {
     if ( sysobjid == desc )
     {
      set_kb_item(name: "Host/dead", value: TRUE);
      security_note(port: 0, extra:'\nSNMP reports it as ' + sysobjids[sysobjid] + '.\n');
      exit(0);
     }
    }
   }

  close(soc);
 }
}



# First try UDP AppSocket

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);
  if ( soc )
  {
  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('UDP AppSocket on port ', port, '\n');
    security_note(port: 0, extra:'\nUDP AppSocket on port ' + port + '.\n');
    exit(0);
   }
  }
}

# Next, BJNP
port = 8611;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);
  if ( soc )
  {
    r = 'BJNP' +
        raw_string(0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    send(socket:soc, data:r);
    r = recv(socket: soc, length: 32);
    if (r && 'BJNP' + raw_string(0x81, 0x01, 0x00, 0x00, 0x00, 0x01) >< r)
    {
      set_kb_item(name: "Host/dead", value: TRUE);
      security_note(port: 0, extra:'\nA Canon-related print service (BJNP) is listening on UDP port ' + port + '.\n');
      exit(0);
    }
  }
}

init_tcp(21, 23, 2002, 9000, 9200, 10000, 79, 80, 280, 443, 631, 7627, 9100);



port = 21;
if( tcp_sockets[port] )
{
 soc = tcp_sockets[port];
 banner = recv_line(socket:soc, length:4096);
 if("JD FTP Server Ready" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('JD FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nJD FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if (egrep(pattern:"^220 [A-Za-z0-9]+ Network Management Card AOS v",string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('APC UPS Management Card FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nAPC UPS Management Card FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if (egrep(pattern:"^220 AXIS .* FTP Network Print Server .+ ready", string:banner))
 {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('AXIS printer FTP server on port ', port, '\n');
    security_note(port:0, extra:'\nAXIS printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ("220 Dell Laser Printer " >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( banner =~ "^220 Dell .* Laser" )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 DPO-[0-9]+ FTP Server", string:banner) )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Toshiba Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nToshiba Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 .* Lexmark.* FTP Server", string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Lexmark Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nLexmark Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ( egrep(pattern:"^220 LANIER .* FTP server", string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('LANIER Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nLANIER Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if ("220 Print Server Ready." >< banner)
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0, extra:'\nGeneric printer FTP server on port ' + port + '.\n');
  exit(0);
 }
 else if (egrep(pattern:"^220 FS-[0-9]+(DN|MFP) FTP server", string:banner))
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port:0, extra:'\nKyocera FTP server on port ' + port + '.\n');
  exit(0);
 }
 else if (
   "220 KONICA MINOLTA FTP server ready" >< banner ||
   "220 KONICAMINOLTA FTP server ready" >< banner
 )
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0, extra:'\nKonica Minolta FTP server on port ' + port + '.\n');
  exit(0);
 }
 else if ( egrep(pattern:"^220 RICOH .* FTP server", string:banner))
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('RICOH Printer FTP server on port ', port, '\n');
    security_note(port: 0, extra:'\nRICOH Printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if (egrep(pattern:"^220 SHARP (MX|AR)- .* FTP server", string:banner))
 {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('Sharp printer FTP server on port ', port, '\n');
    security_note(port:0, extra:'\nSharp printer FTP server on port ' + port + '.\n');
    exit(0);
 }
 else if (egrep(pattern:"^220 ZBR-[0-9]+ Version V", string:banner))
 {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('ZebraNet printer FTP server on port ', port, '\n');
    security_note(port:0, extra:'\nZebraNet printer FTP server on port ' + port + '.\n');
    exit(0);
 }
}

port = 23;
if( tcp_sockets[port] )
{
 soc = tcp_sockets[port];
 banner = telnet_negotiate(socket:soc);
 if ("Network Printer Server Version " >< banner )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Printronix telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nPrintronix Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if("HP JetDirect" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP JetDirect telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nHP JetDirect telnet server on port ' + port + '.\n');
    exit(0);
 }
 if("RICOH Maintenance Shell" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('RICOH Printer telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nRICOH Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if (egrep(pattern:"SHARP (AR|MX)-.+ TELNET server", string:banner))
 {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('Sharp printer telnet server on port ', port, '\n');
    security_note(port:0, extra:'\nSharp printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if ("Copyright (C) 2001-2002 KYOCERA MITA CORPORATION" >< banner )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Kyocera Printer telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nKyocera Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if ("LANIER Maintenance Shell" >< banner )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('LANIER telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nLANIER Printer telnet server on port ' + port + '.\n');
    exit(0);
 }
 if ('\n\n\nDGS-1210-48 login: ' >< banner)
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  debug_print('DGS-1210-48 telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nD-Link DGS-1210-48 management interface on port ' + port + '.\n');
    exit(0);
 }

 if (
  '\r\nThis session allows you to set the TCPIP parameters for your\r\nDell Laser Printer' >< banner &&
  'Network Firmware Version is' >< banner
 )
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  debug_print('Dell Laser Printer telnet server on port ', port, '\n');
  security_note(port: 0, extra:'\nDell Laser Printer telnet server on port ' + port + '.\n');
  exit(0);
 }
 if ('ZebraNet' >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('ZebraNet telnet server on port ', port, '\n');
    security_note(port: 0, extra:'\nZebraNet Printer telnet management interface on port ' + port + '.\n');
    exit(0);
 }

}


# Xerox DocuPrint
port = 2002;
if ( get_port_state(port) )
{
 soc = tcp_sockets[port];
 if ( soc )
 {
  banner = recv(socket:soc, length:23);
  if ( banner && 'Please enter a password' >< banner ) {
    	set_kb_item(name: "Host/dead", value: TRUE);
    	security_note(port: 0, extra:'\nXerox DocuPrint service on port ' + port + '.\n');
	exit(0);
	}
 }
}

# Lexmark
port = 9000;
if ( get_port_state(port) )
{
 soc = tcp_sockets[port];
 if ( soc )
 {
  send(socket:soc, data: '\r\n');
  banner = recv(socket:soc, length:1024);
  if (
    banner &&
    (
     '************************************************************\r\n\r\nThis session allows you to set the TCPIP parameters for your\r\nLexmark ' >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0, extra:'\nLexmark Telnet session on port ' + port + '.\n');
    exit(0);
  }
 }
}

# Dell laser printers (5310n at least).
port = 9200;
if (get_port_state(port))
{
  soc = tcp_sockets[port];
  if (soc)
  {
    banner = recv(socket:soc, length:48, min:31);

    if (banner)
    {
      if (
        stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "Dell Laser Printer ")) == 1 ||
        stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "Lexmark ")) == 1
      )
      {
        set_kb_item(name:"Host/dead", value:TRUE);
        model = substr(banner, 5, strlen(banner) - 2);
        security_note(port:0, extra:'\nA '+model+' is listening on port ' + port + ' for raw\nconnections.\n');
        exit(0);
      }
      else if (stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "ML-1630 Series")) == 1)
      {
        set_kb_item(name:"Host/dead", value:TRUE);
        security_note(port:0, extra:'\nPrint Server Identification service on port ' + port + ' (Samsung laser printer).\n');
        exit(0);
      }
    }
  }
}

# Lexmark
port = 10000;
if ( get_port_state(port) )
{
 soc = tcp_sockets[port];
 if ( soc )
 {
  banner = recv(socket:soc, length:16);
  if (banner && banner == 'LXK: ')
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0, extra:'\nLexmark NDMP service on port ' + port + '.\n');
    exit(0);
  }
 }
}

# Lexmark Optra returns on finger port:
# Parallel port 1
# Printer Type: Lexmark Optra LaserPrinter
# Print Job Status: No Job Currently Active
# Printer Status: 0 Ready

port = 79;
if (get_port_state(port))
{
 soc = tcp_sockets[port];
 if (soc)
 {
   banner = recv(socket:soc, length: 512);
   if (strlen(banner) == 0)
   {
    send(socket: soc, data: 'HELP\r\n');
    banner = recv(socket:soc, length: 512);
   }
   if (banner && 'printer type:' >< tolower(banner))
   {
     set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0, extra:'\nProbable Lexmark printer service on port ' + port + '.\n');
     exit(0);
   }
  }
}

dlink_html1 =
'<html>
<title>Login</title>
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type">
<link rel=stylesheet href="/login_css.css" type="text/css" >
<style type="text/css">
<!--
.portSel { width:145; font-family: Arial}
-->';
dlink_html2 =
'</head>
<body onload=\'document.formLogin.Password.focus();\'>
    <script language="Javascript">
    if(window.screen.width == 1280){
        document.write("<div name=tabBigTitleLogin id=tabBigTitleLogin class=tabBigTitleLogin style=\'left:500;\'>");
    }else {
        document.write("<div name=tabBigTitleLogin id=tabBigTitleLogin class=tabBigTitleLogin>");
    }

        document.write("<table><tr><div class=imgBigTitle><td valign=top noWrap>&nbsp;&nbsp;&nbsp;<font class=tdBigTitle>Connect to "+deviceIP+"</font>");
    </script>

        <img name=imgBigTitleLogin id=imgBigTitleLogin class=imgBigTitleLogin src=\'/lightblue.jpg\'>
        <img name=imgBigTitleLoginKey id=imgBigTitleLoginKey class=imgBigTitleLoginKey src=\'/login_key.jpg\'></td></div></tr>
    </table></div>


    <form name=formLogin id=formLogin method=post action="/" target=\'_top\'>
    <table name=tabLoginContent id=tabLoginContent class=tabLoginContent>
        <tr><td colspan=2>Enter your password</td>
        <tr><td colspan=2>&nbsp;</td>
        <tr><td width=100>Password</td>
            <td><input class=flatL type="password" name="Password" id=Password maxlength=20></td>' ;

# Patch by Laurent Facq
ports = make_list(80, 280, 443, 631, 7627);
foreach port (ports)
{

 if(get_port_state(port))
 {
  soc = tcp_sockets[port];
  if ( !soc ) continue;
  send(socket:soc, data:'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n');
  banner = http_recv(socket:soc);
  if(empty_or_null(banner)) continue;
  # Check to see if the device redirected us to another page, and follow
  if ( "301 Moved Permanently" >< banner ||
       "302 Found" >< banner
     )
  {
    goHere = eregmatch(pattern:"Location[ \t]*:[ \t]*([^\r\n]*)($|[\r\n]+)", string:banner);
    if(empty_or_null(goHere)) continue;
    goHereNow = goHere[1];
    send(socket:soc, data:'GET ' + goHereNow + ' HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n');
    banner = http_recv(socket:soc);
  }

  if(
    "Dell Laser Printer " >< banner ||
    (
      "Server: EWS-NIC4/" >< banner &&
      "Dell MFP Laser" >< banner
    ) ||
    (
      "<title>Dell Laser MFP</title>" >< banner &&
      "//GXI_FAX_INSTALL" >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Dell printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell printer-related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (
    # eg,
    #    Server: EWS-NIC4/11.68
    #    ...
    #    <title>DocuPrint C3290 FS - FX80FE5E</title>
    "Server: EWS-NIC4/" >< banner &&
    "<title>DocuPrint " >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('A DocuPrint-related web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA DocuPrint-related web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    banner &&
    "SERVER: EPSON_Linux UPnP" >< banner &&
    "<title>Epson Stylus" >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('An Epson-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nAn Epson related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (
    banner &&
    (
      "<title>Integrated PrintNet Enterprise Home Page</title>" >< banner ||
      (
        'COT Interface Adapter System 2' >< banner &&
        '<tr><td><a href="STATUS"><img src="btn_play.gif" alt="Execute" border="0"></a></td><td>Status page</td></tr>' >< banner
      )
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Printronix related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nPrintronix related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (banner &&
           'WWW-Authenticate: Basic realm="APC Management Card"' >< banner &&
           egrep(pattern:"^Server: Allegro-Software-RomPager/", string:banner))
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('APC UPS Management Card on port ', port, '\n');
    security_note(port: 0, extra:'\nAPC UPS Management Card on port '+ port+ '.\n');
    exit(0);
  }
  else if (
    (
      "Server: $ProjectRevision: " >< banner &&
      '<title>HP LaserJet' &&
      '<td><div class="mastheadPhoto"><img src="/Images/masthead.jpg" alt="Printer Cartridges">'
    ) ||
    ("<title>Hewlett Packard</title>" >< banner) ||
    egrep(pattern:"<title>.*LaserJet.*</title>", string:banner, icase:TRUE) ||
    ("SERVER: HP-ChaiSOE/" >< banner)  ||
    ("Server: HP-ChaiSOE/" >< banner)  ||
    ("Server: HP-ChaiServer/" >< banner)  ||
    (
      "Server: Virata-EmWeb/" >< banner &&
      (
        "<title> HP Color LaserJet " >< banner ||
        "<title>HP Photosmart" >< banner ||
        "window.top.location.href='./index.htm?cat=info&page=printerInfo'" >< banner ||
        (
          "document.writeln('"+'<frame src="" name="PhoneHome"' >< banner &&
          'At the middle is <a href="index_top_2.htm"> Tabs Frame.</a><br />' >< banner
        )
      )
    ) ||
    (
      (
        "SERVER: HP-ChaiSOE/" >< banner ||
        "Server: HP-ChaiSOE/" >< banner
      ) &&
      "/hp/device/this.LCDispatcher" >< banner
    ) ||
    ("Server: HP_Compact_Server" >< banner)
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer-related web server on port '+ port+ '.\n');
    exit(0);
  }
  else if (
    banner &&
    (
      "Server: Xerox_MicroServer/Xerox" >< banner ||
      ("Server: Webserver" >< banner && "XEROX WORKCENTRE" >< banner) ||
      ("Server: Apache" >< banner && "XEROX WORKCENTRE" >< banner && "function SyncTreeToThisUrl" >< banner) ||
      "Fuji Xerox Co., Ltd. All Rights Reserved. -->" >< banner ||
      (
        "Server: Allegro-Software-RomPager/" >< banner &&
        '<meta content="printer; embedded web server' >< banner &&
        "Model=ColorQube" >< banner &&
        "XEROX CORPORATION" >< banner
      )
    )
  )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Xerox web server on port ', port, '\n');
    security_note(port: 0, extra:'\nXerox web server on port ' + port + '.\n');
    exit(0);
  }
  else if ( 
    banner &&
    (
      (
        "Server: Rapid Logic/" >< banner && 
        "EqualLogic Group Manager" >!< banner &&
        "com.equallogic.eqlgroupmgr.EqlGroupMgrApplet" >!< banner
      ) ||
      ("Server: Virata-EmWeb" >< banner && report_paranoia > 1)
    )
  )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('HP printer: Rapid-Logic / Virata-EmWeb on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer: Rapid-Logic / Virata-EmWeb on port ' + port + '.\n');
    exit(0);
  }
 else if(banner && "Fiery" >< banner )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('Fiery WebTools on port ', port, '\n');
    security_note(port: 0, extra:'\nFiery WebTools on port ' + port + '.\n');
    exit(0);
  }
  else if (banner && "Server: Web-Server/" >< banner)
  {
   if (
    (
     "<title>Web Image Monitor" >< banner &&
     'location.href="/web/guest/en/websys/webArch/mainFrame.cgi' >< banner
    ) ||
    (
     '<FRAME SRC="/en/top_head.cgi" NAME="header"' >< banner &&
     '<FRAME SRC="/en/top_main.cgi" NAME="mainmenu"' >< banner
    )
   )
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('RICOH web server on port ', port, '\n');
    security_note(port: 0, extra:'\nRicoh web server on port ' + port + '.\n');
    exit(0);
   }
  }
  else if ( '\nServer:' >!< banner && dlink_html1 >< banner && dlink_html2 >< banner )
    {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('D-Link web server on port ', port, '\n');
    security_note(port: 0, extra:'\nD-Link web server on port ' + port + '.\n');
    exit(0);
    }
  else if (
    (
      "Server: KM-MFP-http/V" >< banner &&
      (
        "<title>Kyocera Command Center" >< banner ||
        'frame name=wlmframe  src="/startwlm/Start_Wlm.htm"' >< banner
      )
    ) ||
    (
      "HTTP/1.1 302 Movtmp" >< banner &&
      "Content-Type: text/html" >< banner && 
      egrep(pattern:"^Location: https://.+:443/", string:banner)
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('A Kyocera web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Kyocera web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    '<title class="clsTitle1">TopAccess' >< banner &&
    'location.href.indexOf("?MAIN=EFILING") == -1) ? "TopAccess" : eFilingTitle' >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('A Toshiba e-Studio web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Toshiba e-Studio web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    (
      'href="/sws/images/fav.ico"' >< banner &&
      'function RedirectToSWS()' >< banner &&
      'var debugMode = ("' >< banner
    ) ||
    (
      '<title>SyncThru Web Service</title>' >< banner &&
      egrep(pattern:'var COPYRIGHT =.+ SAMSUNG\\. All rights reserved\\.";', string:banner)
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('A Dell or Samsung SyncThru Web Service is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Dell or Samsung SyncThru Web Service is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    '"refresh" content="0; URL=/wcd/js_error.xml"' >< banner &&
    'onload="location.replace(\'/wcd/index.html\');"' >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    debug_print('A SINDOH printer web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA SINDOH printer web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    (
      "Server: KS_HTTP/" >< banner &&
      '<meta http-equiv=author content="Canon Inc."' >< banner
    ) ||
    (
      "Server: CANON HTTP Server Ver" >< banner &&
      "function goto_country(){" >< banner
    ) ||
    (
      "Server: CANON HTTP Server" >< banner &&
      egrep(pattern:"[Uu][Rr][Ll]\s?=\s?.+:8000/rps/", string:banner)
    )
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    security_note(port:0, extra:'\nA Canon printer on port ' + port + '.\n');
    exit(0);
  }
  else if (
    'Brother MFC-' >< banner &&
    ('Printer Settings' >< banner ||
     'Brother Industries' >< banner)
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('A Brother MFC printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Brother MFC printer web server is listening on port '+port+'.\n');
    exit(0);
  }
else if (
    'Server: KM-MFP-http/' >< banner &&
    '/wlm/index.htm' >< banner
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('A Konica printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Konica printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (">KONICA MINOLTA PageScope Web Connection for magicolor" >< banner)
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('A Konica Minolta printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Konica Minolta printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (
    '<title>Network Print Server</title' >< banner &&
    'WARNING: Contact with the print server will be lost a while, during the restart' >< banner &&
    egrep(pattern:'<td>&nbsp;&nbsp;<b>AXIS [0-9][^ ]+</b></td>', string:banner)
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    debug_print('An AXIS printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nAn AXIS printer web server is listening on port '+port+'.\n');
    exit(0);
  }
 }	# get_port_state
}

port = 9100;
if (get_port_state(port))
{
  soc = tcp_sockets[port];
  if (soc)
  {
    send(socket: soc, data: '\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n');
    r = recv(socket: soc, length: 1024);
    if (! isnull(r) && '@PJL INFO ID\r\n' >< r )
    {
      set_kb_item(name: "Host/dead", value: TRUE);
      security_note(port: 0, extra:'\nA PJL service is listening on port ' + port + '.\n');
      exit(0);
    }
  }
}
