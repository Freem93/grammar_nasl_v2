#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83768);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/03 20:48:28 $");

  script_name(english:"Cisco TelePresence IP VCR Detection");
  script_summary(english:"Uses FTP to identify TelePresence IP VCR devices.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus detected a remote video conferencing device.");
  script_set_attribute(attribute:"description", value:
"Nessus has determined that the remote host is a multipoint control
unit video teleconferencing device.");
  # http://www.cisco.com/c/en/us/products/collaboration-endpoints/telepresence-ip-vcr-series/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28dd74bc");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_ip_vcr_2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_ip_vcr_3.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

device = NULL;
version = NULL;
detected = FALSE;

ftp_port_list = get_kb_list("Services/ftp");
if (isnull(ftp_port_list)) ftp_port_list = make_list();
ftp_port_list = add_port_in_list(list:ftp_port_list, port:21);

foreach port (ftp_port_list)
{
  banner = get_ftp_banner(port:port);
  if (empty_or_null(banner)) continue;

  if (
    ('Cisco TelePresence' >< banner || 'Codian' >< banner) &&
    'IP VCR' >< banner
  )
  {
    detected = TRUE;
    set_kb_item(name:"Cisco/TelePresence_IP_VCR", value:TRUE);

    d_match = eregmatch(
      pattern:"^.*IP VCR ([^,]+)($|,)",
      string:banner,
      icase:TRUE
    );
    v_match = eregmatch(
      pattern:"version ([0-9.()]+)([^0-9.()]|$)",
      string:banner,
      icase:TRUE
    );

    if (!isnull(d_match)) device = "IP VCR " + d_match[1];
    else device = UNKNOWN_VER;

    if (!isnull(v_match)) version = v_match[1];
    else version = UNKNOWN_VER;

    set_kb_item(name:"Cisco/TelePresence_IP_VCR/Device", value:device);
    set_kb_item(name:"Cisco/TelePresence_IP_VCR/Version", value:version);
    break;
  }
}

if (!detected) audit(AUDIT_HOST_NOT, "Cisco TelePresence IP VCR");

if (report_verbosity > 0)
{
  report = '\n  Device           : ' + device +
           '\n  Software version : ' + version +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
