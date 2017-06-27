#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21118);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_cve_id("CVE-2006-1338");
  script_bugtraq_id(17161);
  script_osvdb_id(24014);

  script_name(english:"MailEnable Webmail Malformed Encoded Quoted-printable Email DoS (CVE-2006-1338)");
  script_summary(english:"Checks version of MailEnable");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service issue." );
  script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

According to its banner, using the webmail service bundled with the
version of MailEnable Enterprise Edition on the remote host to view
specially-formatted quoted-printable messages reportedly can result in
100% CPU utilization." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/professionalhistory.asp" );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/enterprisehistory.asp" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional Edition 1.73 / Enterprise Edition
1.21 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/22");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("smtp_func.inc");

port = get_http_port(default:8080, embedded: 1);

# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (!banner) exit(1, "No HTTP banner on port "+port);
if (!egrep(pattern:"^Server: .*MailEnable", string:banner))
 exit(0, "MailEnable is not running on port "+port);


# Check the version number from the SMTP server's banner.
smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0, "Port "+smtp_port+" is closed");
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0, "MTA on port "+smtp_port+" is broken");

banner = get_smtp_banner(port:smtp_port);
if (! banner) exit(1, "No SMTP banner on port "+smtp_port);
if (banner !~ "Mail(Enable| Enable SMTP) Service") exit(0, "MailEnable is not running on port "+smtp_port);

  # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
  #     Professional Edition formats it like "0-1.2-" (for 1.2), and
  #     Enterprise Edition formats it like "0--1.1" (for 1.1).
  ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
  if (!isnull(ver))
  {
    if (ver[1] == NULL) edition = "Standard";
    else if (ver[1] == "0-") edition = "Professional";
    else if (ver[1] == "0--") edition = "Enterprise";
  }
  if (isnull(ver) || isnull(edition)) exit(1);
  ver = ver[2];

  # nb: Professional versions < 1.73 are vulnerable.
  if (edition == "Professional")
  {
    if (ver =~ "^1\.([0-6]|7($|[0-2]))") security_warning(port);
  }
  # nb: Enterprise Edition versions < 1.21 are vulnerable.
  else if (edition == "Enterprise")
  {
    if (ver =~ "^1\.([01]([^0-9]|$)|2$)") security_warning(port);
  }
