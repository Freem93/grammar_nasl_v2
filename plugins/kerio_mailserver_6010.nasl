#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18256);
  script_version("$Revision: 1.13 $");

  script_bugtraq_id(13616);
  script_osvdb_id(16486, 16487);

  script_name(english:"Kerio MailServer < 6.0.10 Multiple Mail Handling DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to multiple denial of service
attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.0.10.  In those versions, crashes can occur when
downloading certain email messages in IMAP or Outlook with Kerio
Outlook Connector (KOC) or, under Linux, when parsing email messages
with multiple embedded 'eml' attachments." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.0.10 or newer." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"RedHat JBoss File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/12");
 script_cvs_date("$Date: 2013/05/18 00:28:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_summary(english:"Checks for Kerio MailServer < 6.0.10");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("http.inc");


# Try to get the web server's banner.
ports_l = get_kb_list("Services/www");
foreach port (ports_l)
{
  banner = get_http_banner(port:port);
  if (
  banner && 
  egrep(pattern:"^Server: Kerio MailServer ([0-5].*|6\.0\.[0-9][^0-9]?)", string:banner)
) {
  security_warning(port);
  exit(0);
  }
}


# If that failed, try to get the version from the SMTP server.
ports_l = get_kb_list("Services/smtp");
if ( !isnull(ports_l) ) ports_l = make_list(ports_l);
else ports_l = make_list();
ports_l = add_port_in_list(list: ports_l, port: 25);
foreach port (ports_l)
{
  banner = get_smtp_banner(port:port);
  if (
  banner && 
  egrep(pattern:"^220 .* Kerio MailServer ([0-5].*|6\.0\.[0-9][^0-9]?)", string:banner)
  ) {
  security_warning(port);
  exit(0);
  }
}
