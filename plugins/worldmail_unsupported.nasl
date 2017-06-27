#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60015);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(51403);
  script_osvdb_id(78304);
  script_xref(name:"EDB-ID", value:"18354");

  script_name(english:"Eudora WorldMail Unsupported");
  script_summary(english:"Checks for evidence of WorldMail server");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an unsupported mail server.");
  script_set_attribute(attribute:"description", value:
"According to a network service banner, Eudora WorldMail server is
running on the remote host. Eudora WorldMail is no longer supported by
QUALCOMM.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.eudora.com/worldmail/");
  script_set_attribute(attribute:"solution", value:"Migrate to another mail server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qualcomm:eudora_worldmail");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mailma", 106, "Services/pop3", 110, "Services/smtp", 25, "Services/imap", 143);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("imap_func.inc");
include("smtp_func.inc");
include("pop3_func.inc");

report = NULL;
report_port = 0;

appname = "WorldMail";
imap_ports = get_kb_list('Services/imap');
if (isnull(imap_ports)) imap_ports = make_list(143);

smtp_ports = get_kb_list("Services/smtp");
if (isnull(smtp_ports)) smtp_ports = make_list(25);

pop_ports = get_kb_list("Services/pop3");
if (isnull(pop_ports)) pop_ports = make_list(110);

management_port = get_service(svc: "mailma", default: 106, exit_on_fail: FALSE);

banner = get_service_banner_line(service:"mailma", port:management_port);
if (
  banner &&
  egrep(pattern:"WorldMail( [0-9\.]+ | )Mail Management Server \([0-9\.]+\) ready", string:banner)
)
{
  report = '\n  Mail management server banner : \n' + banner;
  report_port = management_port;
}

if (!report)
{
  # check all the imap ports
  foreach port (imap_ports)
  {
    banner = get_imap_banner(port:port);
    if (isnull(banner)) continue;

    if (egrep (pattern:"WorldMail( [0-9\.]+ | )IMAP4 Server", string:banner))
    {
      report = '\n  IMAP banner : \n' + banner;
      report_port = port;
      break;
    }
  }
}

if (!report)
{
  # check all the smtp ports
  foreach port (smtp_ports)
  {
    banner = get_smtp_banner(port:port);
    if (isnull(banner)) continue;

    if (egrep (pattern:"WorldMail( [0-9\.]+ | )ESMTP Receiver Version ([0-9\.]+) Ready", string:banner))
    {
      report = '\n  SMTP banner : \n' + banner;
      report_port = port;
      break;
    }
  }
}

if (!report)
{
  # check all the pop3 ports
  foreach port (pop_ports)
  {
    banner = get_pop3_banner(port:port);
    if (isnull(banner)) continue;

    if (egrep (pattern:"WorldMail( [0-9\.]+ | )POP3 Server ([0-9\.]+) Ready", string:banner))
    {
      report = '\n  POP3 banner : \n' + banner;
      report_port = port;
      break;
    }
  }
}

if (!isnull(report))
{
  register_unsupported_product(product_name:"Eudora WorldMail",
                               cpe_base:"qualcomm:eudora_worldmail");
  report =
'\nThe following service banner indicates that WorldMail is installed on\n' +
'the remote host :\n' +  report;

  if (report_verbosity > 0) security_hole(port:report_port, extra:report);
  else security_hole(report_port);
  exit(0);
}
else  audit(AUDIT_NOT_DETECT, appname);
