#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57977);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/04 16:15:43 $");

  script_name(english:"Oracle WebCenter Content Detection");
  script_summary(english:"Detects Oracle WebCenter Content");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a web-based content management system."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Oracle WebCenter Content (formerly known as Enterprise Content
Management), a web-based content management system, was found to be
running on the remote host."
  );
  # http://www.oracle.com/technetwork/middleware/webcenter/content/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57aacaee");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Oracle WebCenter Content";

function parse_version(version)
{
  local_var item, versions;

  versions = make_array();

  # try to parse 11.1.1.8 version
  # 11.1.1.8.0-2013-07-11 17:07:21Z-r106802
  # 11.1.1.8.0PSU-2013-09-13 15:21:10Z-r110081
  item = eregmatch(pattern: "^([0-9.]+)(?:PSU|)-[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:Z]+-r([0-9]+)$",
                   string: version);
  if(!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  # try to parse 10.x version
  # 10.1.3.5.1 (130612)
  item = eregmatch(pattern: "^([0-9.]+)[ ]*\(([0-9]+)\)[ ]*$",
                   string: version);
  if(!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  # try to parse 11.x version
  # 11gR1-11.1.1.7.0-idcprod1-130304T092605
  item = eregmatch(pattern: "^[^-]+-([0-9.]+)-[^-]+-([0-9T]+)$",
                   string: version);
  if(!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  return versions;
}

port = get_http_port(default:80);

dirs = make_list("/cs", "/idc", "/");

install_found = FALSE;

foreach dir (dirs)
{
  url = dir + "/idcplg?IdcService=GET_ENVIRONMENT&IsJson=1";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    '"ProductVersion"' >< res[2] &&
    '"ContentManagement"' >< res[2] &&
    '"IdcService"' >< res[2] && '"IsJson"' >< res[2]
  )
  {
    # "ProductVersion": "11gR1-11.1.1.7.0-idcprod1-130304T092605",
    item = eregmatch(pattern:'"ProductVersion"[ \t]*:[ \t]*"([^"]+)"', string:res[2]);
    if (!isnull(item[1]))
      version = item[1];

    versions = parse_version(version: version);

    if(!isnull(versions['main_ver']) && !isnull(versions['sub_ver']))
    {
      version = versions['main_ver'] + " (" + versions['sub_ver'] + ")";
    }
    else
    {
      version = UNKNOWN_VER;
    }

    install_found = TRUE;

    register_install(
      app_name : app_name,
      path     : dir,
      version  : version,
      port     : port,
      cpe      : "cpe:/a:oracle:fusion_middleware",
      webapp   : TRUE
    );

    if(!thorough_tests) break;
  }
}

if (!install_found) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

report_installs(port:port);
