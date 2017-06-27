#
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 2645	On-Demand Mail Relay (ODMR) SMTP with Dynamic IP Addresses
#

include("compat.inc");

if (description)
{
  script_id(18391);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_name(english:"SMTP Server Non-standard Port Detection");
  script_summary(english:"An SMTP server is running on a non-standard port");

  script_set_attribute(attribute:"synopsis", value:"The remote SMTP service is running on a non-standard port.");
  script_set_attribute(
    attribute:"description",
    value:
"This SMTP server is running on a non-standard port.  This might be a
backdoor set up by attackers to send spam or even control of a targeted
machine."
  );
  script_set_attribute(attribute:"solution", value:"Check and clean the configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"see_also", value:"http://www.icir.org/vern/papers/backdoor/");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Backdoors");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp");
  exit(0);
}

#

include("global_settings.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) exit(0, "The host does not appear to be running an SMTP server.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");

# 25 SMTP
# 366 CommuniGate Pro SMTP Module
# 465 SMTP SSL
# 475 Exchange Server 2013 mailbox role communications
# 587 Submission (RFC 4409)
# 717 Exchange Server 2013 CAS Server for mail from trusted mailbox servers
# 2525 Exchange Server 2013

if (
  port != 25 && 
  port != 366 && 
  port != 465 && 
  port != 475 && 
  port != 587 && 
  port != 717 && 
  port != 2525
)
{
  banner = get_smtp_banner(port:port);
  if (report_verbosity > 0 && banner)
  {
    report = '\n  Banner : ' + banner + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
