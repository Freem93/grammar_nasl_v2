#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64457);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/05 00:46:00 $");

  script_name(english:"Ekiga SIP Detection");
  script_summary(english:"Detects Ekiga SIP Service");

  script_set_attribute(attribute:"synopsis", value:"Ekiga is running on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote SIP service is from Ekiga, a voice-over-IP (VoIP)
application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ekiga.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ekiga:ekiga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installed = FALSE;
errors = make_list();

foreach protocol (make_list("tcp", "udp"))
{

  if (protocol == "tcp")
    ports = get_kb_list("Services/sip");
  else
    ports = get_kb_list("Services/udp/sip");

  if (!ports) continue;

  foreach port (make_list(ports))
  {
    if (protocol == 'tcp')
      banner = get_kb_item("sip/banner/"+port);
    else
      banner = get_kb_item("sip/banner/"+protocol+"/"+port);
   
    if (!banner) continue;
    if ("Ekiga" >!< banner) continue;

    matches = eregmatch(pattern:"^Ekiga\/([A-Za-z0-9.]+)", string:banner);
    if (!matches)
    {
      errors = make_list(errors, "Could not parse version from Ekiga banner on port "+protocol+"/"+port);
      continue;
    }

    replace_kb_item(name:"ekiga/sip_detected", value:TRUE);
  
    # Set a KB item so that we know its Ekiga on a certain port
    set_kb_item(name:"sip/ekiga/" + protocol + "/" + port + "/source", value:chomp(banner));
   
    ver = matches[1];
    set_kb_item(name:"sip/ekiga/" + protocol + "/" + port + "/version", value:ver);
    installed = TRUE;

    if (report_verbosity > 0)
    {
      report_header = '\nNessus found the following Ekiga SIP service';

      report = report_header +
                  '\n    SIP banner : ' + banner +
                  '\n    Version    : ' + ver + '\n';
      security_note(port:port, proto:protocol,extra:report);
    }
    else security_note(port:port, proto:protocol);
  }
}

if (!installed)
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');
  
    exit(1, errmsg);
  }
  else audit(AUDIT_NOT_INST, "Ekiga");
}
