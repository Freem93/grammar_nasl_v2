#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57913);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/07/07 17:20:51 $");

  script_name(english:"Backported Security Patch Detection (SMTP)");
  script_summary(english:"Checks for backported SMTP banners.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Security patches are backported."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security patches may have been 'backported' to the remote SMTP server
without changing its version number. 

Banner-based checks have been disabled to avoid false positives. 

Note that this test is informational only and does not denote any
security problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/updates/backporting/?sc_cid=3093"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/smtp", 25, 587);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

ports = make_list();
if (!isnull(get_kb_list("Services/smtp")))
{
  ports = make_list(get_kb_list("Services/smtp"));
}

foreach port (make_list(25, 587))
{
  if (service_is_unknown(port:port))
  {
    ports = add_port_in_list(list:ports, port:port);
  }
}
if (isnull(ports)) audit(AUDIT_NOT_INST, "An SMTP server");


foreach port (ports)
{
  banner = get_smtp_banner(port:port);
  if (strlen(banner) == 0) continue;

  banner2 = get_backport_banner(banner:banner);
  if (banner != banner2)
  {
    if (report_verbosity > 0)
    {
      if (get_kb_item("Host/local_checks_enabled"))
        info = "Local checks have been enabled.";
      else
        info = "Give Nessus credentials to perform local checks.";

      info = '\n' + info + '\n';
      security_note(port:port, extra:info);
    }
    else security_note(port);
  }
}
