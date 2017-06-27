# This script was written by Laurent Facq <facq@u-bordeaux.fr> 05/2004
#
# 99% based on dont_scan_printers by Michel Arboi <arboi@alussinan.org>
#
#
# Released under GPLv2
#
# plugin : dont_print_on_printers.nasl

## after suggesting a way to avoid paper wasting, i happilly saw appearing a new plugin 'dont_scan_printers'
## but i rapidly saw also that when safe_checks is off (what i use) - HP printers continue to
## print wasted pages under nessus assault.

## as far as i know/understand, the really (well, the most) annoying thing (for me) is that 
## "jetdirect" print all what it receive on port 9100/tcp
## so find_services* will flood this port until out of paper :)

## what i do in this script is to mark this port 9100 as known (using  register_service)
## to avoid this discovery flood by find_services*

## so, when safe_check is off, my campus printers will no more waste paper :)
## nor when its on because dont_scan_printers will do the job in this case.

## the only draw back, in a security point of view, is that of course, you can fool
## nessus to not really scan 9100 port... buf said.

## the http code (port 80 and 280) i wrote here could be added to the original 'dont_scan_printers' code
## because i saw that my HP 4000N was not detected as a HP jet printer (no telnet, no ftp, but http)

## well, i only 99% understood the end of the original script (treating the case of a lot of open ports...), 
## but i kept it in case it could do a good job.

# Changes by Tenable:
# - Revised plugin title (9/10/09)

include("compat.inc");

if(description)
{
 script_id(12241); 
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/03/11 20:33:08 $"); 

 script_name(english:"AppSocket & socketAPI Printers - Do Not Scan");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a printer and will not be scanned.");
 script_set_attribute(attribute:"description", value:
"The host seems to be an AppSocket or socketAPI printer.  Scanning it
will likely waste paper.  Therefore, port 9100 won't be scanned.");
 script_set_attribute(attribute:"solution", value:
"n/a");
 script_set_attribute(attribute:"risk_factor", value:
"None");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2004/05/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Exclude port 9100 on AppSocket & socketAPI printers from scan");
 script_category(ACT_SETTINGS);
# script_add_preference(name:"Exclude 9100 printers port from scan", type:"checkbox", value:"no");
  script_copyright(english:"This script is Copyright (C) 2004-2011 by Laurent Facq");
 script_family(english:"Settings");
# Or maybe a "scan option" family?
 exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");
include("telnet_func.inc");

include("misc_func.inc");
include("http_func.inc");


# pref= script_get_preference("Exclude 9100 printers port from scan");
# if (!pref || pref == "no") exit(0);

#### only usefull if safe_check not wanted (dont_scan_printers will do the job in this other case)
if (safe_checks()) exit(0);
####

# First try UDP AppSocket

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);

  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
  {
    # set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0);

    register_service(port: 9100, proto: "ignore-this-printer-port");

    exit(0);
  }
}

port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if("JD FTP Server Ready" >< banner ||
 # MA 2008-08-30
 # I got this banner:
 #  220 LXKF44256 IBM Infoprint 1140 FTP Server 54.10.24 ready. 
 # Ports 9000, 9100 & 9200 were first open and later closed
 # Did the printer crash?
 " IBM Infoprint " >< banner ||
 " MarkNet X2012e FTP Server " >< banner	# MA: this is an HP Laserjet?
 )
 {
     #    set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0);
     
     register_service(port: 9100, proto: "ignore-this-printer-port");
     
     exit(0);
 }
}

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("HP JetDirect" >< banner)
 {
     #set_kb_item(name: "Host/dead", value: TRUE);

     register_service(port: 9100, proto: "ignore-this-printer-port");

    security_note(port: 0);
    exit(0);
 }
}


ports = make_list(80, 280);
foreach port (ports)
{
 if(get_port_state(port))
 {
  banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
  if("<title>Hewlett Packard</title>" >< banner)
  {
     #    set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0);
     
     register_service(port: 9100, proto: "ignore-this-printer-port");
     
     exit(0);
  }
 }
}



# open ports?
ports = get_kb_list("Ports/tcp/*");

# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4990.html
appsocket = 0;


foreach p (keys(ports))
{
  p = int(p - "Ports/tcp/");
  if (	   p == 35		# AppSocket for QMS
	|| p == 2000		# Xerox
	|| p == 2501		# AppSocket for Xerox
	|| (p >= 3001 && p <= 3005)	# Lantronix - several ports
	|| (p >= 9100 && p <= 9300)	# AppSocket - several ports
        || p == 10000 		# Lexmark
	|| p == 10001)		# Xerox - programmable :-(
    appsocket = 1;
# Look for common non-printer ports
	 else if (
          p != 21              # FTP
       && p != 23              # telnet
       && p != 79
       && p != 80              # www
       && p != 139 && p!= 445  # SMB
       && p != 280             # http-mgmt
       && p != 443
       && p != 515             # lpd
       && p != 631 	       # IPP
       && p != 8000 
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers    
	exit(0);

}

# OK, this might well be an AppSocket printer
if (appsocket)
{
  security_note(0);

  register_service(port: 9100, proto: "ignore-this-printer-port");

  #set_kb_item(name: "Host/dead", value: TRUE);
}
