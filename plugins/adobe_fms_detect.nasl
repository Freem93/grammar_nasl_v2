#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50705);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/09/10 19:41:30 $");

  script_name(english:"Adobe Flash Media Server Version Detection");
  script_summary(english:"Attempts to get an Adobe Flash Media Server version number.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server reports its version number in HTTP headers.");
  script_set_attribute(attribute:"description", value:
"Adobe Flash Media Server, a data and media server that serves
applications to Flash Player, appears to be running on the remote host
and is reporting its version number in HTTP headers.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashmediaserver/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_media_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("rtmp_detect.nasl", "http_version.nasl");
  script_require_ports("Services/rtmp", 1111, 1935, 19350);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/rtmp"), port:1111);
ports = add_port_in_list(list:ports, port:1935);
ports = add_port_in_list(list:ports, port:19350);

info  = NULL;
fms_present_on_host = FALSE;
pattern = 'FlashCom/([0-9][^ ]*)';

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  http_disable_keep_alive();
  res = http_send_recv3(method:"GET", item:"/fcs/ident", port:port, fetch404:TRUE);
  if (isnull(res)) continue;

  # Check for Wowza server
  if ('wowza' >< tolower(res[2])) continue;

  headers = parse_http_headers(headers:res[1]);
  if (isnull(headers) || !headers['server'] || "FlashCom" >!< headers['server']) continue;

  set_kb_item(name:"rtmp/adobe_fms", value:TRUE);
  fms_present_on_host = TRUE;

  matches = eregmatch(string:headers['server'], pattern:pattern);
  if (isnull(matches)) continue;

  source  = headers['server'];
  version = matches[1];

  set_kb_item(name:"rtmp/"+port+"/adobe_fms/version", value:version);
  set_kb_item(name:"rtmp/"+port+"/adobe_fms/version_source", value:source);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
if (!fms_present_on_host) audit(AUDIT_NOT_INST, 'Adobe Flash Media Server');
