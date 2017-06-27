#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93741);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/27 20:06:43 $");

  script_name(english:"Apple TV Version Detection");
  script_summary(english:"AppleTV version detection.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version and model of the remote Apple TV
device.");
  script_set_attribute(attribute:"description", value:
"The remote host is an Apple TV device. Nessus was able to obtain its
version and model information via an HTTP request for the
'/server-info' resource.");
  script_set_attribute(attribute:"see_also", value:"https://www.apple.com/tv/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("appletv_detect.nasl", "http_version.nasl");
  script_require_ports(7000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:7000);

# If we already have AppleTV information, exit
if (
  !isnull(get_kb_item('AppleTV/Port')) &&
  !isnull(get_kb_item('AppleTV/Model')) &&
  !isnull(get_kb_item('AppleTV/Version')) &&
  !isnull(get_kb_item('AppleTV/URL'))
) exit(0, "This device has already been detected as an AppleTV.");

item = "/server-info";
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : item,
  exit_on_fail:TRUE
);

info = '';

# get model
model_pat = "<key>model</key>\s+<string>AppleTV([0-9]+,[0-9]+)</string>";
model_match = pregmatch(pattern:model_pat, string:res[2], icase:TRUE);

if (isnull(model_match))
{
  if (report_paranoia < 2) exit(0, "The model number for this Apple TV is unknown or invalid.");
}
else
{
  info += '\n  Model         : ' + model_match[1];
  replace_kb_item(name:"AppleTV/Model", value:model_match[1]);
}

# get version
build_pat = "<key>osBuildVersion</key>\s+<string>([A-Za-z0-9]+)</string>";
build_match = pregmatch(pattern:build_pat, string:res[2], icase:TRUE);

if (isnull(build_match)) audit(AUDIT_UNKNOWN_BUILD, "Apple TV");

version = build_match[1];
info += '\n  Build Version : ' + version;
replace_kb_item(name:"AppleTV/Version", value:version);

# get url / port
url = build_url(port:port, qs:'/');
replace_kb_item(name:"AppleTV/URL", value:url);
replace_kb_item(name:"AppleTV/Port", value:port);
url_info = '\n  URL           : ' + url;

info = url_info + info + '\n';

if (!empty_or_null(info))
{
  report = 'Nessus was able to extract the following information' +
           '\nabout the detected AppleTV :' + info;
  security_note(port:port, extra:report);
}
else audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');
