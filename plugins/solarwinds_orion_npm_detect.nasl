#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62117);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/27 13:33:27 $");

  script_name(english:"SolarWinds Orion Product Detection");
  script_summary(english:"Attempts to retrieve the SolarWinds Orion login page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a network monitoring or management
web application.");
  script_set_attribute(attribute:"description", value:
"A SolarWinds Orion product is running on the remote web server. Orion
is a core component of several network monitoring and management
applications.");
  script_set_attribute(attribute:"see_also", value:"http://www.solarwinds.com/network-performance-monitor.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_performance_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_netflow_traffic_analyzer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_ip_address_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_user_device_tracker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_voip_%26_network_quality_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_server_and_application_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_web_performance_monitor");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8787);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "SolarWinds Orion Core";
port = get_http_port(default:8787);

dir = '/Orion';
page_list = make_list('/Login.aspx', '/Login.asp');

kb_base = "www/"+port+"/solarwinds_orion/";

found_install = FALSE;

foreach page (page_list)
{
  url = dir + page;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE, follow_redirect:TRUE);

  if (
    '<title>\r\n\tSolarWinds Orion\r\n</title>' >< res[2] &&
    'User name:' >< res[2]
  )
  {
    version = UNKNOWN_VER;
    extra = make_array();

    # try to parse version information
    item = eregmatch(pattern:'>([^<]*Orion Core[^<]+)<', string:res[2]);
    if (!isnull(item))
    {
      ver_src = item[1];
      set_kb_item(name:kb_base+"version_src", value:ver_src);

      item = eregmatch(pattern:'NPM ([0-9.]+)[^[0-9.]', string:ver_src);
      if (!isnull(item))
      {
        set_kb_item(name:kb_base+"npm_ver", value:item[1]);
        extra['NPM Version'] = item[1];
      }

      item = eregmatch(pattern:'IVIM ([0-9.]+)[^0-9.]', string:ver_src);
      if (!isnull(item))
      {
        set_kb_item(name:kb_base+"ivim_ver", value:item[1]);
        extra['IVIM Version'] = item[1];
      }
      item = eregmatch(pattern:'Orion Core ([0-9.]+)[^0-9.]', string:ver_src);
      if (!isnull(item)) version = item[1];
    }

    register_install(
      app_name : appname,
      port     : port,
      path     : dir,
      version  : version,
      webapp   : TRUE,
      extra    : extra
    );
    found_install = TRUE;
    break;
  }
}

if (!found_install) audit(AUDIT_NOT_DETECT, appname, port);

report_installs(app_name:appname, port:port);
