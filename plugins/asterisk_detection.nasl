#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63202);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/20 16:43:21 $");

  script_name(english:"Asterisk Detection");
  script_summary(english:"Detects Asterisk SIP Service");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a PBX.");
  script_set_attribute(
    attribute:"description",
    value:
"One or more Asterisk SIP services are listening on the remote host.
This is an indication that Asterisk PBX is running on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.asterisk.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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
    if ("Asterisk" >!< banner && "FPBX" >!< banner) continue;

    matches = eregmatch(pattern:"Asterisk PBX[ /]((([A-Z]|\d+)(\.\d+)+)(-[a-z]+\d+|_[a-z])?)", string:banner);
    if (matches)
      ver = matches[1];
    else
    {
      matches = eregmatch(pattern:"FPBX-(\d+(\.\d+)+)\((\d+(\.\d+)+)\)", string:banner);
      if (matches) ver = matches[3];
    }

    # If still no match, log it and continue
    if (!matches)
    {
      errors = make_list(errors, "Could not parse version from Asterisk banner on port "+protocol+"/"+port);
      ver = 'unknown';
    }

    replace_kb_item(name:"asterisk/sip_detected", value:TRUE);

    # Set a KB item so that we know its Asterisk on a certain port
    set_kb_item(name:"sip/asterisk/" + protocol + "/" + port + "/source", value:chomp(banner));
    set_kb_item(name:"sip/asterisk/" + protocol + "/" + port + "/version", value:ver);
    installed = TRUE;

    if (report_verbosity > 0)
    {
      report_header = '\nNessus found the following Asterisk SIP service :';

      report = report_header + 
                  '\n' +
                  '\n  SIP banner : ' + banner +
                  '\n  Version    : ' + ver + '\n';
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
  else audit(AUDIT_NOT_INST, "Asterisk");
}
