#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44920);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2015/06/02 19:49:00 $");

 script_name(english:"Do not scan printers (AppSocket)");
 script_summary(english:"Check ports associated with AppSocket");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a printer and will not be scanned.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a network printer or multi-function
device that supports the AppSocket (also known as JetDirect) protocol. 
Such devices often react very poorly when scanned - some crash, others
print a number of pages.  To avoid problems, Nessus has marked the
remote host as 'Dead' and will not scan it.");
 script_set_attribute(attribute:"solution", value:
"If you are not concerned about such behavior, enable the 'Scan
Network Printers' setting under the 'Do not scan fragile devices'
advanced settings block and re-run the scan.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 exit(0);
}

include("global_settings.inc");

if ( islocalhost()) exit(0,"No need to check localhost.");

if ( get_kb_item("Scan/Do_Scan_Printers" ) ) exit(0, "The 'Scan/Do_Scan_Printers' KB item is set.");

# open ports?
ports = get_kb_list("Ports/tcp/*");
# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0,"The 'Ports/tcp/*' KB items are missing.");

# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0, "More than 8 ports are open.");

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
#        || p == 10000 		# Lexmark
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
       && p != 631             # IPP
       && p != 6101            # Port 6101 is used by Zebra Printers
       && p != 8000
       && p != 10002
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers
	exit(0, "Port "+ p +" a common non-printer port is open.");
}

if (appsocket)
{
  banner23 = get_kb_item("Banner/23");
  if ("Nortel Networks" >< banner23) appsocket = 0;
}

# OK, this might well be an AppSocket printer
if (appsocket) 
{
  security_note(port:0, extra:'\nThe remote host seems to be an AppSocket printer.');
  debug_print('Looks like an AppSocket printer.\n');
  set_kb_item(name: "Host/dead", value: TRUE);
}
else exit(0, "The host does not listen on a port used by AppSocket.");
