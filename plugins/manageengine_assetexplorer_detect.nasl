#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63692);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/11/09 22:26:45 $");

  script_name(english:"ManageEngine AssetExplorer Detection");
  script_summary(english:"Checks for ManageEngine AssetExplorer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an asset management application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine AssetExplorer, a web-based
asset management application.");
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/asset-explorer/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoho:manageengine_assetexplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "ManageEngine AssetExplorer";
port = get_http_port(default:8080);

installs = 0;

url = "/";
res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if (
  '<title>ManageEngine AssetExplorer</title>' >< res && 
  egrep(pattern:'[0-9]+ (AdventNet Inc|ZOHO Corporation|ZOHO Corp)', string:res)
) 
{
  version = NULL;
  ver_pat   = ">version&nbsp;([0-9.]+[^<])</div>";
  build_pat = "IncludeSDPScripts.js\?build=([0-9]+)";
  matches = egrep(pattern:ver_pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:ver_pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  if (!isnull(version))
  {
    matches = egrep(pattern:build_pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:build_pat, string:match);
        if (!isnull(item))
        {
          version += " Build " + item[1];
          break;
        }
      }
    }
  }

  # Save info about the install.
  register_install(
    app_name : appname,
    path : "",
    port : port,
    version : version,
    cpe : "cpe:/a:zoho:manageengine_assetexplorer",
    webapp: TRUE
  );

  installs++;

}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
report_installs(port:port);
