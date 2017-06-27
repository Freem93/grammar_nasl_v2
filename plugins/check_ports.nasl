#
# (C) Tenable Network Security, Inc.
#

# Services known to crash or freeze on a port scan:
#
# ClearCase (TCP/371)
# NetBackup
# gnome-session on Solaris
#
################
# References
################
#
# From: marek.rouchal@infineon.com
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#   submissions@packetstormsecurity.org
# CC: rheinold@rational.com, buggy@segmentationfault.de,
#    Thorsten.Delbrouck@guardeonic.com, manfred.korger@infineon.com
# Date: Fri, 22 Nov 2002 10:30:11 +0100
# Subject: ClearCase DoS vulnerabilty
#
# CVE-2008-5684
#
################
# Changes
################
#
# Edited by Herman Young <herman@sensepost.com>

include("compat.inc");

if (description)
{
 script_id(10919);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2014/06/04 10:51:55 $");

 script_name(english:"Open Port Re-check");
 script_summary(english:"Check if ports are still open");

 script_set_attribute(attribute:"synopsis", value:"Previously open ports are now closed.");
 script_set_attribute(attribute:"description", value:
"One of several ports that were previously open are now closed or
unresponsive.

There are several possible reasons for this :

  - The scan may have caused a service to freeze or stop
    running.

  - An administrator may have stopped a particular service
    during the scanning process.

This might be an availability problem related to the following :

  - A network outage has been experienced during the scan,
    and the remote network cannot be reached anymore by the
    scanner.

  - This scanner may has been blacklisted by the system
    administrator or by an automatic intrusion detection /
    prevention system that detected the scan.

  - The remote host is now down, either because a user
    turned it off during the scan or because a select denial
    of service was effective.

In any case, the audit of the remote host might be incomplete and may
need to be done again.");
 script_set_attribute(attribute:"solution", value:
"- Increase checks_read_timeout and/or reduce max_checks.

- Disable any IPS during the Nessus scan");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("find_service1.nasl");
 script_exclude_keys("Host/dead");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function malware_is_running_on_port(port)
{
  local_var	l, s;
  if (get_kb_item('backdoor/TCP/'+port) ||
      get_kb_item('ftp/'+port+'/broken') ||
      get_kb_item('ftp/'+port+'/backdoor') )
   return 1;

  l = get_kb_list('ftp/'+port+'/backdoor');
  if ( !isnull(l) ) return 1;

  l = get_kb_list('Known/tcp/'+port);
  foreach s (l)
    if (s == 'malware-distribution')
      return 1;
    else if (s == '220backdoor')
      return 1;
  return 0;
}


if (get_kb_item("Host/dead")) exit(0, "The remote host was found to be dead.");

#
# Do not do a false positive if netstat or the snmp
# port scanners have been used.
#
if (get_kb_item("Host/scanners/netstat")) exit(0, "The Netstat port scanner was used to enumerate ports.");
if (get_kb_item("Host/scanners/snmp_scanner") ) exit(0, "The SNMP port scanner was used to enumerate ports.");

ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0, "No TCP ports were found to be open.");

number_of_ports = 0;
closed_ports = 0;

read_timeout = get_read_timeout();
timeout = 2 * read_timeout;	# Make sure we don't miss something.

myreport = "";

foreach port (keys(ports))
{
   number_of_ports ++;
   port = int(port - "Ports/tcp/");
   if ( port == 139 || port == 445 ) continue;
   if (malware_is_running_on_port(port: port)) continue;
   k = strcat('/tmp/ConnectTimeout/TCP/', port);
   vk = get_kb_item(k);
   if (vk)
   {
     replace_kb_item(name: k, value: 0);
     rm_kb_item(name:k);	# Works if Nessus >= 3.2
     myreport = strcat(myreport, 'Port ', port, ' was detected as being open initialy but was found unresponsive later.\n It is now ');
   }

   then = unixtime();
   s = open_sock_tcp(port, timeout: timeout);
   now = unixtime();
   if (! s)
   {
     if (! vk)
  	myreport = strcat(myreport, 'Port ', port, " was detected as being open but is now ");
     else
       replace_kb_item(name: k, value: vk);

	if (now - then < timeout - 1)
	  myreport += 'closed\n';
	else
	  myreport += 'unresponsive\n';
	closed_ports++;
   }
   else
   {
     if (vk) myreport += 'open.\n';
     rm_kb_item(name:k);	# Just in case
     close(s);
   }
}


if (number_of_ports == 0) exit(0, "No ports were retested.");
else if (closed_ports == 0) exit(0, "None of the retested ports were found to be closed.");
else
{
  if (report_verbosity > 0) security_note(port:0, extra:myreport);
  else security_note(0);
}
