#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55455);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"Trend Micro Data Loss Prevention Virtual Appliance Web Console Detection");
  script_summary(english:"Detects Trend Micro Data Loss Prevention Virtual Appliance Web Console");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts Trend Micro DLP Web Console.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts an instance of Trend Micro Data Loss
Prevention (DLP) Web Console."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);

dirs = make_list('/dsc', cgi_dirs());
dirs = list_uniq(dirs);

foreach dir (dirs)
{
  url = dir+'/';
  res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

  if ('<title>Trend Micro Data Loss Prevention Logon</title>' >< res)
  {
    # Get build number and version if possible
    matches = NULL;
    version = NULL;
    build_number = NULL;
    tmp_versions = make_list();

    res = http_send_recv3(item:url + 'au/env_1/dlp_manager_config.ini', port:port, method:"GET", exit_on_fail:TRUE);
    lines = egrep(string:res[2], pattern:"_manager_.*type.*build");

    if (!isnull(lines) && lines != "")
    {
      # Loop over patch and hotfix entry and keep the largest version and build number
      foreach line (split(lines, keep:FALSE))
      {
        matches = eregmatch(string:line, pattern:"<(pb|hfb)([0-9]+)_manager_([0-9]+\.[0-9]+)\.([0-9]+)");
        if (!isnull(matches))
        {
          if ('type="patch"' >< line)
            tmp_versions = make_list(tmp_versions, matches[3] + "." + matches[4]); # patch
          else
            tmp_versions = make_list(tmp_versions, matches[3] + "." + matches[2]); # hotfix
        }
      }
      tmp_versions = sort(tmp_versions);
      version = tmp_versions[max_index(tmp_versions) -1];
    }
    # must get version from another page and build number from current page
    else
    {
      matches = eregmatch(string:res[2], pattern:'<init_hotfix.*build_no="([0-9]+)');
      if (!isnull(matches)) build_number = matches[1];

      # get version number from a help page
      res = http_send_recv3(item:url + 'HIE/help/WebHelp/DataLossPrevention/Chapter_1_-_Introduction/Welcome.htm', port:port, method:"GET",exit_on_fail:TRUE);
      matches = eregmatch(string:res[2], pattern:"<h1>Data Loss Prevention Endpoint ([0-9.]+)</h1>");
      if (!isnull(matches)) version = matches[1];

      if (build_number) version += "." + build_number;
    }

    installs = add_install(
      installs:installs,
      dir:dir,
      ver:version,
      appname:'trendmicro_dlpva_web_console',
      port:port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs))
  exit(0, 'Trend Micro Data Loss Prevention Web Console wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Trend Micro Data Loss Prevention Web Console',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
