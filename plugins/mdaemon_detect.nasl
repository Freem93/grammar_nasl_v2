#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66633);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/28 14:57:12 $");

  script_name(english:"Alt-N MDaemon Detection");
  script_summary(english:"Detects MDaemon Services");

  script_set_attribute(attribute:"synopsis", value:"A mail server running on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"MDaemon, a multi-protocol email and messaging server, is running on the
remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.altn.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25, 366, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("misc_func.inc");


errors = make_list();
protos = make_list('smtp', 'pop3', 'imap');
pattern = " \(?M[Dd]aemon (FREE |ready using UNREGISTERED SOFTWARE |Mail Server )?[Vv]?\(?(([0-9][0-9.a-zA-Z]+)( SP[0-9]+)?( R)?)\)?";

smtp_ports = make_list(25, 366, 587);
pop3_ports = make_list(110, 995);
imap_ports = make_list(143, 993);

foreach proto (protos)
{
  ports = make_list();
  if (proto == "smtp") potential_ports = smtp_ports;
  if (proto == "pop3") potential_ports = pop3_ports;
  if (proto == "imap") potential_ports = imap_ports;
  foreach pport (potential_ports)
  {
    if (service_is_unknown(port:pport))
      ports = make_list(ports, pport);
  }

  detected_ports = get_kb_list("Services/"+proto);
  if (!isnull(detected_ports))
    ports = list_uniq(make_list(ports, make_list(detected_ports)));

  foreach port (ports)
  {
    version = NULL;
    source  = NULL;
    matches = NULL;
    banner  = NULL;

    if (proto == "smtp") banner = get_smtp_banner(port:port);
    if (proto == "pop3") banner = get_pop3_banner(port:port);
    if (proto == "imap") banner = get_imap_banner(port:port);

    if (!banner)
    {
      errors = make_list(errors, "Unable to obtain MDaemon banner on port "+port);
      continue;
    }
    if (" MDaemon " >!< banner && " Mdaemon " >!< banner) continue;

    matches = egrep(pattern:pattern, string: banner);
    if (!matches)
    {
      # Remote service is likely MDaemon, but we can't get
      # the version. Mark version 'unknown' and log issue.
      version = 'unknown';
      # Grab 'source' with less specificity for records
      buf = egrep (pattern:" M[Dd]aemon ", string:banner);
      if (buf)
      {
        lines = split(buf, keep:FALSE);
        source = lines[0];
      }
      else source = 'unknown';
      errors = make_list(errors, "Unable to parse version from MDaemon banner on port "+port);
    }
    else
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pattern, string:match);
        if (isnull(item)) continue;

        source = strip(match);
        version = item[2];
        break;
      }
    }

    replace_kb_item(name:"mdaemon/installed", value:TRUE);
    installed = TRUE;

    if ("POP3" >< source) display_proto = "POP3";
    else if ("POP" >< source) display_proto = "POP";
    else if ("ESMTP" >< source) display_proto = "ESMTP";
    else if ("SMTP" >< source) display_proto = "SMTP";
    else if ("IMAP" >< source) display_proto = "IMAP";
    else display_proto = "unknown";

    set_kb_item(name:"mdaemon/port", value:port);
    set_kb_item(name:"mdaemon/"+port+"/version", value:version);
    set_kb_item(name:"mdaemon/"+port+"/source", value:source);
    set_kb_item(name:"mdaemon/"+port+"/proto", value:display_proto);

    if (report_verbosity > 0)
    {
      report =
        '\n' +
        '\n    Service           : ' + display_proto +
        '\n    Source            : ' + source +
        '\n    Installed version : ' + version +
        '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}

if (!installed)
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:';\n  ');
    exit(1, errmsg);
  }
  else audit(AUDIT_NOT_INST, "MDaemon");
}
