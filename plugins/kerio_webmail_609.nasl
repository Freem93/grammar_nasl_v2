#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18058);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1138");
  script_bugtraq_id(13180);
  script_osvdb_id(15551);

  script_name(english:"Kerio MailServer Webmail Malformed Email Handling Resource Exhaustion DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.0.9.  Such versions may be subject to hangs or
high CPU usage when malformed email messages are viewed through its
WebMail component.  An attacker may be able leverage this issue to deny
service to legitimate users simply by sending a specially crafted
message and having that message viewed by someone using Kerio WebMail." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.0.9 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/13");
 script_cvs_date("$Date: 2012/08/14 16:26:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_summary(english:"Checks for Kerio MailServer < 6.0.9");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
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
  egrep(pattern:"^Server: Kerio MailServer ([0-5].*|6\.0\.[0-8])", string:banner)
) {
  security_hole(port);
  exit(0);
}
}

# If that failed, try to get the version from the SMTP server.
ports_l = get_kb_list("Services/smtp");
ports_l = add_port_in_list(list: ports_l, port: 25);
foreach port (ports_l)
{
banner = get_smtp_banner(port:port);
if (
  banner && 
  egrep(pattern:"^220 .* Kerio MailServer ([0-5].*|6\.0\.[0-8]) ESMTP ready", string:banner)
) {
  security_hole(port);
  exit(0);
}
}
