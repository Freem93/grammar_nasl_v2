#
# (C) Tenable Network Security, Inc.
#

# Credits: Berend-Jan Wever

include("compat.inc");

if (description)
{
  script_id(11270);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_name(english:"Multiple Anti-Virus SMTP Message Long Line Parsing DoS");
  script_summary(english:"Sends a long line to the MTA");

  script_set_attribute(attribute:'synopsis', value:"The remote SMTP server is vulnerable to denial of service.");
  script_set_attribute(attribute:'description', value:
"Some antivirus scanners die when they process an email with a long
string without line breaks.

Such a message was sent. If there is an antivirus on your MTA, it
might have crashed. Please check its status right now, as it is not
possible to do it remotely");
  script_set_attribute(attribute:'solution', value:
"This plugin tests for a generic condition. It may be remedied by
upgrading, reconfiguring, or changing your email antivirus solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");

  script_dependencie("smtpserver_detect.nasl", "smtp_settings.nasl", "smtp_relay.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

fromaddr = smtp_from_header();
toaddr = smtp_to_header();

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

b = strcat('From: ', fromaddr, '\r\n', 'To: ', toaddr, '\r\n',
	'Subject: Nessus test - ignore it\r\n\r\n',
	crap(10000), '\r\n');
n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (n > 0) security_warning(port);
